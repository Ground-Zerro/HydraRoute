#ifndef PROBE_HTTP_H
#define PROBE_HTTP_H

#include <stdint.h>
#include <stddef.h>

int http_request_prefix(const uint8_t *data, size_t len);
int http_headers_end(const uint8_t *data, size_t len);
int http_extract_host(const uint8_t *data, size_t len, char *host, size_t host_size);

#endif
