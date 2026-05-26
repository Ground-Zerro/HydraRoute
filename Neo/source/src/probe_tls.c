#include "../include/probe_tls.h"
#include <string.h>

static inline uint16_t pntoh16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static inline uint32_t pntoh24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static inline int is_handshake_hello_clienthello(const uint8_t *data, size_t len) {
    return len >= 6 &&
           data[0] == 0x01 &&
           data[4] == 0x03 &&
           data[5] <= 0x03;
}

int tls_quick_check(const uint8_t *data, size_t len) {
    return len >= 11 &&
           data[0] == 0x16 &&
           data[1] == 0x03 &&
           data[2] <= 0x03 &&
           data[5] == 0x01;
}

static int tls_find_ext_len_offset_in_handshake(const uint8_t *data, size_t len, size_t *off) {
    size_t l = 1 + 3 + 2 + 32;
    if (len < l + 1) return 0;
    l += data[l] + 1;
    if (len < l + 2) return 0;
    l += pntoh16(data + l) + 2;
    if (len < l + 1) return 0;
    l += data[l] + 1;
    if (len < l + 2) return 0;
    *off = l;
    return 1;
}

static int tls_find_ext_in_handshake(const uint8_t *data, size_t len, uint16_t type,
                                     const uint8_t **ext, size_t *len_ext) {
    size_t l;
    if (!tls_find_ext_len_offset_in_handshake(data, len, &l)) return 0;

    data += l; len -= l;
    l = pntoh16(data);
    data += 2; len -= 2;

    if (len < l) l = len;

    while (l >= 4) {
        uint16_t etype = pntoh16(data);
        size_t elen = pntoh16(data + 2);
        data += 4; l -= 4;
        if (l < elen) break;
        if (etype == type) {
            if (ext && len_ext) {
                *ext = data;
                *len_ext = elen;
            }
            return 1;
        }
        data += elen; l -= elen;
    }
    return 0;
}

static int tls_advance_to_host_in_sni(const uint8_t **ext, size_t *elen, size_t *slen) {
    if (*elen < 5 || (*ext)[2] != 0) return 0;
    uint16_t nll = pntoh16(*ext);
    *slen = pntoh16(*ext + 3);
    if (nll < (*slen + 3) || *slen > *elen - 5) return 0;
    *ext += 5; *elen -= 5;
    return 1;
}

int tls_extract_sni(const uint8_t *data, size_t len, char *host, size_t host_size) {
    if (!tls_quick_check(data, len)) return 0;
    if (!is_handshake_hello_clienthello(data + 5, len - 5)) return 0;

    size_t reclen = (size_t)pntoh16(data + 3) + 5;
    if (reclen < len) len = reclen;

    const uint8_t *ext;
    size_t elen;
    if (!tls_find_ext_in_handshake(data + 5, len - 5, 0, &ext, &elen)) return 0;

    size_t slen;
    if (!tls_advance_to_host_in_sni(&ext, &elen, &slen)) return 0;

    if (!host || host_size == 0) return 1;
    if (slen >= host_size) slen = host_size - 1;
    for (size_t i = 0; i < slen; i++) {
        uint8_t c = ext[i];
        host[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
    }
    host[slen] = '\0';
    return 1;
}
