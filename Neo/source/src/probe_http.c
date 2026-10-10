#include "../include/probe_http.h"
#include "../include/probe_tls.h"
#include <string.h>

static inline int is_host_at(const uint8_t *p) {
    return p[0] == '\n' &&
           (p[1] == 'H' || p[1] == 'h') &&
           (p[2] == 'o' || p[2] == 'O') &&
           (p[3] == 's' || p[3] == 'S') &&
           (p[4] == 't' || p[4] == 'T') &&
           p[5] == ':';
}

int http_request_prefix(const uint8_t *data, size_t len) {
    if (len == 0) return 0;
    for (size_t i = 0; i < 9 && i < len; i++) {
        if (data[i] == ' ') return i >= 2;
        if (!(data[i] >= 'A' && data[i] <= 'Z')) return 0;
    }
    return len < 9;
}

int http_headers_end(const uint8_t *data, size_t len) {
    for (size_t i = 3; i < len; i++)
        if (data[i] == '\n' && data[i - 1] == '\r' && data[i - 2] == '\n' && data[i - 3] == '\r') return 1;
    return 0;
}

int http_extract_host(const uint8_t *data, size_t len, char *host, size_t host_size) {
    if (len < 7) return 0;

    const uint8_t *p = NULL;
    if (len >= 6) {
        size_t scan_end = len - 6;
        for (size_t pos = 0; pos <= scan_end; pos++) {
            if (is_host_at(data + pos)) {
                p = data + pos + 1;
                break;
            }
        }
    }
    if (!p) return 0;

    const uint8_t *e = data + len;
    p += 5;
    while (p < e && (*p == ' ' || *p == '\t')) p++;
    const uint8_t *s = p;
    while (s < e && *s != '\r' && *s != '\n' && *s != ' ' && *s != '\t' && *s != ':') s++;
    if (s == e) return 0;
    return host_copy(p, (size_t)(s - p), host, host_size);
}
