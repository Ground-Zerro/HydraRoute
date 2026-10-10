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

int tls_record_prefix(const uint8_t *data, size_t len) {
    return len > 0 && data[0] == 0x16 &&
           (len < 2 || data[1] == 0x03) &&
           (len < 3 || data[2] <= 0x03) &&
           (len < 6 || data[5] == 0x01);
}

int tls_quick_check(const uint8_t *data, size_t len) {
    return len >= 11 && tls_record_prefix(data, len);
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

int host_copy(const uint8_t *s, size_t n, char *out, size_t out_size) {
    if (n && s[n - 1] == '.') n--;
    if (n == 0 || n > 253 || n >= out_size) return 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = s[i];
        if (c >= 'A' && c <= 'Z') c |= 0x20;
        else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                   c == '-' || c == '.' || c == '_'))
            return 0;
        out[i] = (char)c;
    }
    out[n] = '\0';
    return 1;
}

int tls_handshake_sni(const uint8_t *hs, size_t len, char *host, size_t host_size) {
    const uint8_t *ext;
    size_t elen, slen;
    if (!is_handshake_hello_clienthello(hs, len)) return 0;
    if (!tls_find_ext_in_handshake(hs, len, 0, &ext, &elen)) return 0;
    if (!tls_advance_to_host_in_sni(&ext, &elen, &slen)) return 0;
    return host_copy(ext, slen, host, host_size);
}
