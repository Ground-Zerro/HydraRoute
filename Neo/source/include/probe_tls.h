#ifndef PROBE_TLS_H
#define PROBE_TLS_H

#include <stdint.h>
#include <stddef.h>

int tls_quick_check(const uint8_t *data, size_t len);
int tls_extract_sni(const uint8_t *data, size_t len, char *host, size_t host_size);

#endif
