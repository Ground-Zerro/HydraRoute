#ifndef TESTS_PKT_H
#define TESTS_PKT_H

#include "../include/quic_crypto.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define QUIC_MIN_PLAIN 1200

typedef struct {
    uint8_t b[1500];
    size_t n;
} pkt_t;

static inline void put8(pkt_t *p, uint8_t v) { p->b[p->n++] = v; }
static inline void put16(pkt_t *p, uint16_t v) { put8(p, (uint8_t)(v >> 8)); put8(p, (uint8_t)v); }

static inline void put_name(pkt_t *p, const char *name) {
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t len = dot ? (size_t)(dot - name) : strlen(name);
        put8(p, (uint8_t)len);
        memcpy(p->b + p->n, name, len);
        p->n += len;
        name += len + (dot ? 1 : 0);
    }
    put8(p, 0);
}

static inline void dns_header(pkt_t *p, uint16_t id, uint16_t ancount) {
    p->n = 0;
    put16(p, id); put16(p, 0x8180); put16(p, 1); put16(p, ancount); put16(p, 0); put16(p, 0);
    put_name(p, "www.example.com");
    put16(p, 1); put16(p, 1);
}

static inline void rr_head(pkt_t *p, uint16_t type, uint32_t ttl) {
    put16(p, type); put16(p, 1);
    put16(p, (uint16_t)(ttl >> 16)); put16(p, (uint16_t)ttl);
}

static inline void add_cname(pkt_t *p, uint32_t ttl, const char *target) {
    put16(p, 0xC00C);
    rr_head(p, 5, ttl);
    size_t at = p->n;
    put16(p, 0);
    put_name(p, target);
    uint16_t rd = (uint16_t)(p->n - at - 2);
    p->b[at] = (uint8_t)(rd >> 8); p->b[at + 1] = (uint8_t)rd;
}

static inline void add_a(pkt_t *p, uint16_t owner_ptr, uint32_t ttl, uint8_t last) {
    put16(p, owner_ptr);
    rr_head(p, 1, ttl);
    put16(p, 4);
    put8(p, 198); put8(p, 51); put8(p, 100); put8(p, last);
}

static inline size_t client_hello(uint8_t *out, const char *sni, size_t pad) {
    size_t n = strlen(sni), p = 0;
    out[p++] = 0x01;
    p += 3;
    out[p++] = 0x03; out[p++] = 0x03;
    memset(out + p, 0x5A, 32); p += 32;
    out[p++] = 0;
    out[p++] = 0; out[p++] = 2; out[p++] = 0x13; out[p++] = 0x01;
    out[p++] = 1; out[p++] = 0;
    size_t ext_len_at = p;
    p += 2;
    size_t ext_start = p;
    out[p++] = 0x00; out[p++] = 0x15;
    out[p++] = (uint8_t)(pad >> 8); out[p++] = (uint8_t)pad;
    memset(out + p, 0, pad); p += pad;
    out[p++] = 0; out[p++] = 0;
    out[p++] = (uint8_t)((n + 5) >> 8); out[p++] = (uint8_t)(n + 5);
    out[p++] = (uint8_t)((n + 3) >> 8); out[p++] = (uint8_t)(n + 3);
    out[p++] = 0;
    out[p++] = (uint8_t)(n >> 8); out[p++] = (uint8_t)n;
    memcpy(out + p, sni, n); p += n;
    size_t ext_len = p - ext_start;
    out[ext_len_at] = (uint8_t)(ext_len >> 8);
    out[ext_len_at + 1] = (uint8_t)ext_len;
    size_t body = p - 4;
    out[1] = (uint8_t)(body >> 16); out[2] = (uint8_t)(body >> 8); out[3] = (uint8_t)body;
    return p;
}

static inline size_t tls_record(uint8_t *rec, const char *sni, size_t pad) {
    size_t n = client_hello(rec + 5, sni, pad);
    rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x01;
    rec[3] = (uint8_t)(n >> 8); rec[4] = (uint8_t)n;
    return n + 5;
}

typedef struct {
    uint8_t key[16], iv[12], hp[16];
} quic_keys_t;

static inline void quic_derive(int v2, const uint8_t *dcid, size_t dcil, quic_keys_t *k) {
    static const uint8_t salt_v1[20] = {
        0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
        0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a
    };
    static const uint8_t salt_v2[20] = {
        0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,
        0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9
    };
    uint8_t initial[32], client[32];
    hkdf_extract(v2 ? salt_v2 : salt_v1, 20, dcid, dcil, initial);
    hkdf_expand_label(initial, "client in", client, 32);
    hkdf_expand_label(client, v2 ? "quicv2 key" : "quic key", k->key, 16);
    hkdf_expand_label(client, v2 ? "quicv2 iv" : "quic iv", k->iv, 12);
    hkdf_expand_label(client, v2 ? "quicv2 hp" : "quic hp", k->hp, 16);
}

typedef struct {
    size_t off, len;
} frag_t;

static inline size_t put_varint(uint8_t *p, uint64_t v) {
    if (v < 64) { p[0] = (uint8_t)v; return 1; }
    p[0] = (uint8_t)(0x40 | (v >> 8)); p[1] = (uint8_t)v; return 2;
}

static inline size_t quic_crypto_frames(uint8_t *plain, const uint8_t *ch, const frag_t *fr, int nfr) {
    size_t pl = 0;
    for (int i = 0; i < nfr; i++) {
        plain[pl++] = 0x01;
        plain[pl++] = 0x06;
        pl += put_varint(plain + pl, fr[i].off);
        pl += put_varint(plain + pl, fr[i].len);
        memcpy(plain + pl, ch + fr[i].off, fr[i].len);
        pl += fr[i].len;
    }
    return pl;
}

static inline size_t quic_pad(uint8_t *plain, size_t pl) {
    while (pl < QUIC_MIN_PLAIN) plain[pl++] = 0x00;
    return pl;
}

static inline size_t quic_protect(uint8_t *out, int v2, const uint8_t *plain, size_t pl) {
    static const uint8_t dcid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    size_t p = 0;
    out[p++] = v2 ? 0xD3 : 0xC3;
    uint32_t ver = v2 ? 0x6b3343cfu : 1u;
    out[p++] = (uint8_t)(ver >> 24); out[p++] = (uint8_t)(ver >> 16);
    out[p++] = (uint8_t)(ver >> 8);  out[p++] = (uint8_t)ver;
    out[p++] = sizeof(dcid);
    memcpy(out + p, dcid, sizeof(dcid)); p += sizeof(dcid);
    out[p++] = 0;
    out[p++] = 0;
    size_t payload = 4 + pl + 16;
    out[p++] = (uint8_t)(0x40 | (payload >> 8)); out[p++] = (uint8_t)payload;
    size_t pn_off = p;
    out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 7;

    quic_keys_t k;
    quic_derive(v2, dcid, sizeof(dcid), &k);
    uint8_t nonce[12];
    memcpy(nonce, k.iv, 12);
    nonce[11] ^= 7;
    aes128_ctr_xor(k.key, nonce, 2, plain, out + p, pl);
    p += pl;
    memset(out + p, 0xEE, 16); p += 16;

    uint8_t mask[16];
    aes128_ecb_encrypt(k.hp, out + pn_off + 4, mask);
    out[0] ^= mask[0] & 0x0F;
    for (int i = 0; i < 4; i++) out[pn_off + i] ^= mask[i + 1];
    return p;
}

static inline size_t ip_header(uint8_t *out, int v6, uint8_t proto,
                               const uint8_t *src, const uint8_t *dst, size_t l4_len) {
    if (v6) {
        memset(out, 0, 40);
        out[0] = 0x60;
        out[4] = (uint8_t)(l4_len >> 8); out[5] = (uint8_t)l4_len;
        out[6] = proto; out[7] = 64;
        memcpy(out + 8, src, 16); memcpy(out + 24, dst, 16);
        return 40;
    }
    size_t total = 20 + l4_len;
    memset(out, 0, 20);
    out[0] = 0x45;
    out[2] = (uint8_t)(total >> 8); out[3] = (uint8_t)total;
    out[8] = 64; out[9] = proto;
    memcpy(out + 12, src, 4); memcpy(out + 16, dst, 4);
    return 20;
}

static inline size_t ip_udp(uint8_t *out, int v6, const uint8_t *src, const uint8_t *dst,
                            uint16_t sport, uint16_t dport, const uint8_t *data, size_t len) {
    size_t h = ip_header(out, v6, 17, src, dst, 8 + len);
    uint8_t *u = out + h;
    u[0] = (uint8_t)(sport >> 8); u[1] = (uint8_t)sport;
    u[2] = (uint8_t)(dport >> 8); u[3] = (uint8_t)dport;
    u[4] = (uint8_t)((8 + len) >> 8); u[5] = (uint8_t)(8 + len);
    u[6] = 0; u[7] = 0;
    memcpy(u + 8, data, len);
    return h + 8 + len;
}

static inline size_t ip_tcp(uint8_t *out, int v6, const uint8_t *src, const uint8_t *dst,
                            uint16_t sport, uint16_t dport, uint32_t seq, uint8_t flags,
                            const uint8_t *data, size_t len) {
    size_t h = ip_header(out, v6, 6, src, dst, 20 + len);
    uint8_t *t = out + h;
    memset(t, 0, 20);
    t[0] = (uint8_t)(sport >> 8); t[1] = (uint8_t)sport;
    t[2] = (uint8_t)(dport >> 8); t[3] = (uint8_t)dport;
    t[4] = (uint8_t)(seq >> 24); t[5] = (uint8_t)(seq >> 16);
    t[6] = (uint8_t)(seq >> 8);  t[7] = (uint8_t)seq;
    t[8] = 0; t[11] = 1;
    t[12] = 0x50; t[13] = flags;
    t[14] = 0xFF; t[15] = 0xFF;
    memcpy(t + 20, data, len);
    return h + 20 + len;
}

#endif
