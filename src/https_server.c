/*
 *  HTTPS Server for the ESP32 Chip
 *
 *  Copyright (C) 2018, Micah Carrick
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_system.h"
#include "esp_log.h"

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#ifdef CONFIG_MBEDTLS_DEBUG
#include "mbedtls/esp_debug.h"
#endif

#include "http_parser.h"
#include "https_server.h"

static const char *TAG = "https_server";

struct _https_client {
    mbedtls_net_context socket;
    http_parser parser;
    char *uri;
};

struct _https_server {
    TaskHandle_t task;
    uint8_t status;
    uint16_t port;
    mbedtls_x509_crt x509_crt;
    mbedtls_pk_context pk_context;
    mbedtls_ctr_drbg_context ctr_drbg_context;
    mbedtls_entropy_context entropy_context;
    mbedtls_ssl_config ssl_config;
    mbedtls_net_context socket;
    mbedtls_ssl_context ssl_context;
};

/*
FreeRTOS task listening for incoming HTTPS requests.
*/
static void https_server_task(void *pv_parameters)
{
    char err_str[256];  /* mbedtls error strings */
    int r;              /* mbedtls return values */
    https_server_t server = (https_server_t) pv_parameters;

    mbedtls_net_init(&server->socket);

    /* max 5 digits for port based on uint16_t */
    char *port_str = (char*) malloc(sizeof(char) * 5);
    r = mbedtls_net_bind(&server->socket, NULL,
            itoa(server->port, port_str, 10), MBEDTLS_NET_PROTO_TCP);
    free(port_str);

    if (r != 0) {
        mbedtls_strerror(r, err_str, sizeof(err_str));
        ESP_LOGE(TAG, "mbedtls_net_bind: %s", err_str);
        goto exittask;
    }

    ESP_LOGI(TAG, "server running on port %u", server->port);

    while (1) {
        if (server->status == HTTPS_SERVER_STATUS_STOPPING) {
            goto exittask;
        } else {
            server->status = HTTPS_SERVER_STATUS_RUNNING;
        }

        https_client_t _client = (https_client_t) calloc(1, sizeof(*_client));
        mbedtls_net_init(&_client->socket);
        ESP_LOGD(TAG, "waiting for client connect");
        r = mbedtls_net_accept(&server->socket, &_client->socket, NULL, 0, NULL);

        if (r != 0) {
            if (r == MBEDTLS_ERR_NET_ACCEPT_FAILED) {
                /* friendlier error as likley caused by https_server_stop() */
                ESP_LOGW(TAG, "mbedtls_net_accept: connection lost");
            } else {
                mbedtls_strerror(r, err_str, sizeof(err_str));
                ESP_LOGW(TAG, "mbedtls_net_accept: %s", err_str);
            }
            server->status = HTTPS_SERVER_STATUS_STOPPING;
            free(_client);
            continue;
        }

        mbedtls_ssl_set_bio(&server->ssl_context, &_client->socket,
                mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGD(TAG, "beginning TLS handshake");

        while ((r = mbedtls_ssl_handshake_step(&server->ssl_context)) == 0) {
            ESP_LOGD(TAG, "tls handshake state: %d", server->ssl_context.state);
            if (server->ssl_context.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
                break;
            }
        }

        if (r != 0 && r != MBEDTLS_ERR_SSL_WANT_READ
                && r != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_strerror(r, err_str, sizeof(err_str));
            ESP_LOGW(TAG, "mbedtls_ssl_handshake_step: %s", err_str);
            goto disconnect;
        }

disconnect:
        /* disconnect client resources to be re-allocated on next iteration */
        ESP_LOGD(TAG, "resetting session and disconnecting client");
        mbedtls_ssl_session_reset(&server->ssl_context);
        mbedtls_net_free(&_client->socket);
        free(_client);
    }

exittask:
    if (&server->socket != NULL) {
        /* may have already be freed by https_server_stop() */
        mbedtls_net_free(&server->socket);
    }
    server->status = HTTPS_SERVER_STATUS_STOPPED;
    ESP_LOGD(TAG, "server stopped");
    vTaskDelete(NULL);
}

esp_err_t https_server_init(https_server_config_t *config,
                            https_server_t *server)
{
    char err_str[256];  /* mbedtls error strings */
    int r;              /* mbedtls return values */
    https_server_t _server = (https_server_t) calloc(1, sizeof(*_server));

    if (_server == NULL) {
        return ESP_ERR_NO_MEM;
    }

    /* validate config */
    if (config->tls_cert == 0 || config->tls_key == 0) {
        ESP_LOGE(TAG, "missing TLS certificate or key");
        return ESP_FAIL;
    }

    if (config->port == 0) {
        _server->port = HTTPS_SERVER_DEFAULT_PORT;
    } else {
        _server->port = config->port;
    }

    mbedtls_x509_crt_init(&_server->x509_crt);
    mbedtls_pk_init(&_server->pk_context);
    mbedtls_ctr_drbg_init(&_server->ctr_drbg_context);
    mbedtls_entropy_init(&_server->entropy_context);
    mbedtls_ssl_config_init(&_server->ssl_config);
    mbedtls_ssl_init(&_server->ssl_context);

    /* parse TLS certificate and key */
    ESP_LOGD(TAG, "parsing TLS certificate\n%s", config->tls_cert);

    r = mbedtls_x509_crt_parse(&_server->x509_crt,
            config->tls_cert, strlen((char*)config->tls_cert)+1);

    if (r != 0) {
        mbedtls_strerror(r, err_str, sizeof(err_str));
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse: %s", err_str);
        goto cleanup;
    }

    ESP_LOGD(TAG, "parsing TLS private key");
    r = mbedtls_pk_parse_key(&_server->pk_context, config->tls_key,
            strlen((char*)config->tls_key)+1, NULL, 0);

    if (r != 0) {
        mbedtls_strerror(r, err_str, sizeof(err_str));
        ESP_LOGE(TAG, "mbedtls_pk_parse_key: %s", err_str);
        goto cleanup;
    }

    /* seed the RNG */
    uint8_t seed[6];
    esp_efuse_mac_get_default(seed);
    ESP_LOGD(TAG, "CTR_DRBG seed from MAC: %02x:%02x:%02x:%02x:%02x:%02x",
            seed[0], seed[1], seed[2], seed[3], seed[4], seed[5]);
    r = mbedtls_ctr_drbg_seed(&_server->ctr_drbg_context, mbedtls_entropy_func,
            &_server->entropy_context, seed, 6);

    if (r != 0) {
        mbedtls_strerror(r, err_str, sizeof(err_str));
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed: %s", err_str);
        goto cleanup;
    }

    /* setup configuration */
    r = mbedtls_ssl_config_defaults(&_server->ssl_config, MBEDTLS_SSL_IS_SERVER,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

    if (r != 0) {
        mbedtls_strerror(r, err_str, sizeof(err_str));
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults: %s", err_str);
        goto cleanup;
    }

    if (config->tls_ciphersuites != NULL) {
        mbedtls_ssl_conf_ciphersuites(&_server->ssl_config,
                (int*)config->tls_ciphersuites);
    }

    //mbedtls_ssl_conf_ca_chain();
    mbedtls_ssl_conf_own_cert(&_server->ssl_config, &_server->x509_crt,
            &_server->pk_context);

    mbedtls_ssl_conf_rng(&_server->ssl_config, mbedtls_ctr_drbg_random,
            &_server->ctr_drbg_context);

#ifdef CONFIG_MBEDTLS_DEBUG
        mbedtls_esp_enable_debug_log(&_server->ssl_config,
                HTTPS_SERVER_MBED_TLS_DEBUG_LEVEL);
#endif

    r = mbedtls_ssl_setup(&_server->ssl_context, &_server->ssl_config);
    if (r != 0) {
        mbedtls_strerror(r, err_str, sizeof(err_str));
        ESP_LOGE(TAG, "mbedtls_ssl_setup: %s", err_str);
        goto cleanup;
    }

    *server = _server;
    return ESP_OK;

cleanup:
    mbedtls_x509_crt_free(&_server->x509_crt);
    mbedtls_pk_free(&_server->pk_context);
    mbedtls_ctr_drbg_free(&_server->ctr_drbg_context);
    mbedtls_entropy_free(&_server->entropy_context);
    mbedtls_ssl_config_free(&_server->ssl_config);
    mbedtls_ssl_free(&_server->ssl_context);

    return ESP_FAIL;
}

esp_err_t https_server_start(https_server_t server)
{
    ESP_LOGI(TAG, "server starting");
    server->status = HTTPS_SERVER_STATUS_STARTING;
    int r = xTaskCreate(&https_server_task, "https_server",
                        HTTPS_SERVER_TASK_STACK_DEPTH, server,
                        HTTPS_SERVER_TASK_PRIORITY, &server->task);
    if (r == errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY) {
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

void https_server_stop(https_server_t server)
{
    /* set HTTPS_SERVER_STATUS_STOPPING flag to allow graceful shutdown */
    if (server->status != HTTPS_SERVER_STATUS_STOPPED) {
        ESP_LOGI(TAG, "server stopping");
        if (&server->socket != NULL) {
            /* kill server socket to break out of mbedtls_net_accept */
            server->status = HTTPS_SERVER_STATUS_STOPPING;
            mbedtls_net_free(&server->socket);
        } else {
            server->status = HTTPS_SERVER_STATUS_STOPPED;
        }
    }
}

void https_server_free(https_server_t server)
{
    https_server_stop(server);
    ESP_LOGD(TAG, "releasing server");
    mbedtls_x509_crt_free(&server->x509_crt);
    mbedtls_pk_free(&server->pk_context);
    mbedtls_ctr_drbg_free(&server->ctr_drbg_context);
    mbedtls_entropy_free(&server->entropy_context);
    mbedtls_ssl_config_free(&server->ssl_config);
    mbedtls_ssl_free(&server->ssl_context);
    free(server);
}

uint8_t https_server_get_status(https_server_t server) {
    return server->status;
}
