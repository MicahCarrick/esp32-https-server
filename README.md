ESP32 HTTPS Server
==================

HTTPS Web Server for the ESP32 Chip based on the mbed TLS library packaged with
the ESP-IDF SDK.


Quick Start
-----------

Include header file:

```c
#include "https_server.h"
```

Define or load TLS certificates and key.

```c
const uint8_t tls_cert[] = "-----BEGIN CERTIFICATE-----\n\
MIIF6jCCA9KgAwIBAgIJANmaOM7RFLbfMA0GCSqGSIb3DQEBCwUAMIGJMQswCQYD\n\
-----END CERTIFICATE-----\n\n";
/* note: truncated for brevity */

const uint8_t tls_key[] = "-----BEGIN PRIVATE KEY-----\n\
MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQDN3BvDFah/ObFA\n\
-----END PRIVATE KEY-----\n\n";
/* note: truncated for brevity */
```

Define a HTTP response callback function:

```c
https_server_response_t hello_response(https_request_t request,
                                  https_response_t *response,
                                  void *user_args)
{
    char body[] = "<html>\
    <head><title>Hello World</title></head>\
    <body><h1>Hello World</h1></body>\
    </html>";

    https_response_set_body(&response, body);

    return HTTPS_SERVER_RESPONSE_OK;
}
```

Initialize the HTTPS server:
```c
https_server_t server;
https_server_config_t server_config = {};

server_config.port = 443;
server_config.tls_cert = tls_cert;
server_config.tls_key = tls_key;

ESP_ERROR_CHECK(https_server_init(&server_config, &server));
```

Associate routes to HTTP response callback:

```c
ESP_ERROR_CHECK(https_server_add_route(&server, "/hello.html", &hello_response));
```


Establish network connection such as WiFi. See the
[esp-idf wifi examples](https://github.com/espressif/esp-idf/tree/master/examples/wifi) or the
[esp-idf ethernet examples](https://github.com/espressif/esp-idf/tree/master/examples/ethernet/ethernet).

Start the HTTPS server once the ESP32 is connected to a network:

```c
ESP_ERROR_CHECK(https_server_start(server));
```
