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
#ifndef __HTTP_SERVER_H__
#define __HTTP_SERVER_H__

#include "http_parser.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* stack depth allocated to the freeRTOS task used to ruth the https server */
#define HTTPS_SERVER_TASK_STACK_DEPTH       5120

/* priority for the freeRTOS task used to run the https server */
#define HTTPS_SERVER_TASK_PRIORITY          1

/* default port if not specified in https_server_config_t */
#define HTTPS_SERVER_DEFAULT_PORT           443

/* sets mbedtls debug level if CONFIG_MBEDTLS_DEBUG is defined */
#define HTTPS_SERVER_MBED_TLS_DEBUG_LEVEL   4

/* opaque structure representing a single https server */
typedef struct _https_server *https_server_t;

/* opaque structure representing a single https client connection */
typedef struct _https_client *https_client_t;

/* configuration options used to initialize https_server_t */
typedef struct https_server_config_t {
    uint16_t port;                      /* defaults to 443 */
    const uint8_t *tls_cert;            /* TLS certificate bytes */
    const uint8_t *tls_key;             /* TLS key bytes */
    const uint32_t *tls_ciphersuites;   /* optional array of mbedtls cipers */
} https_server_config_t;

/* status is set implicitly by calling init, start, stop, and free functions */
enum HTTPS_SERVER_STATUS {
    HTTPS_SERVER_STATUS_STOPPED,
    HTTPS_SERVER_STATUS_STARTING,
    HTTPS_SERVER_STATUS_RUNNING,
    HTTPS_SERVER_STATUS_STOPPING
};

/**
 * @brief Initialize HTTPS server
 *
 * Setup HTTPS server with configuration options and TLS contexts. Must be freed
 * with https_server_free().
 *
 * @param config[in]    HTTPS server configuration options
 * @param server[out]   HTTPS server being initialized
 *
 * @return ESP_OK
 *         ESP_ERR_NON_MEM
 *         ESP_FAIL
 */
esp_err_t https_server_init(https_server_config_t *config,
                            https_server_t *server);

/**
 * @brief Start HTTPS server
 *
 * Start HTTPS server and listen for incomming client connections.
 *
 * @param server[in]   HTTPS server to be started
 *
 * @return ESP_OK
 *         ESP_ERR_NON_MEM
 */
esp_err_t https_server_start(https_server_t server);

/**
 * @brief Stop HTTPS server
 *
 * Stop HTTPS server without releaseing configuration and TLS contexts. Can be
 * re-started with https_server_start() or destroyed with http_server_free().
 *
 * @param server[in]   HTTPS server to be stopped
 */
void https_server_stop(https_server_t server);

/**
 * @brief Free HTTPS server
 *
 * Stop a HTTPS server and free referenced items and memory.
 *
 * @param server[in]   HTTPS server to be freed
 */
void https_server_free(https_server_t server);

/**
 * @brief Get HTTPS server status
 *
 * Get the current status of the HTTPS server which is set during the various
 * init, start, stop, and free functions.
 *
 * @param server[in]   HTTPS server
 *
 * @return HTTPS_SERVER_STATUS_STOPPED
 *         HTTPS_SERVER_STATUS_STARTING
 *         HTTPS_SERVER_STATUS_RUNNING
 *         HTTPS_SERVER_STATUS_STOPPING
 */
uint8_t https_server_get_status(https_server_t server);

#ifdef __cplusplus
}
#endif
#endif /* __HTTP_SERVER_H__ */
