#include "../include/probe_http.h"
#include <string.h>

static inline int is_host_at(const uint8_t *p) {
    return p[0] == '\n' &&
           (p[1] == 'H' || p[1] == 'h') &&
           (p[2] == 'o' || p[2] == 'O') &&
           (p[3] == 's' || p[3] == 'S') &&
           (p[4] == 't' || p[4] == 'T') &&
           p[5] == ':';
}

int http_quick_check(const uint8_t *data, size_t len) {
    if (len < 8) return 0;
    if (!(data[0] >= 'A' && data[0] <= 'Z')) return 0;
    if (!(data[1] >= 'A' && data[1] <= 'Z')) return 0;
    for (size_t i = 0; i < 9 && i < len; i++) {
        if (data[i] == ' ') return 1;
        if (!(data[i] >= 'A' && data[i] <= 'Z')) return 0;
    }
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
    if (p >= e) return 0;

    const uint8_t *s = p;
    if (*s == '[') {
        const uint8_t *q = s + 1;
        while (q < e && *q != ']' && *q != '\r' && *q != '\n') q++;
        if (q < e && *q == ']') s = q + 1;
        else s = q;
    } else {
        while (s < e && *s != '\r' && *s != '\n' && *s != ' ' && *s != '\t' && *s != ':') s++;
    }

    if (s <= p) return 0;

    size_t slen = (size_t)(s - p);
    if (!host || host_size == 0) return 1;
    if (slen >= host_size) slen = host_size - 1;
    for (size_t i = 0; i < slen; i++) {
        uint8_t c = p[i];
        host[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
    }
    host[slen] = '\0';
    return 1;
}
