#ifndef PROBE_TLS_H
#define PROBE_TLS_H

#include <stdint.h>
#include <stddef.h>

int tls_record_prefix(const uint8_t *data, size_t len);
int tls_quick_check(const uint8_t *data, size_t len);
int tls_handshake_sni(const uint8_t *hs, size_t len, char *host, size_t host_size);
int host_copy(const uint8_t *s, size_t n, char *out, size_t out_size);

#endif
