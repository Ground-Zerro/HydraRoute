#ifndef CRYPTO_ASM_H
#define CRYPTO_ASM_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define CRYPTO_ASM_RANGES 8

typedef struct {
    uint16_t lo, hi;
} asm_range_t;

typedef struct {
    uint8_t    *buf;
    uint16_t    cap;
    uint16_t    total;
    uint8_t     nranges;
    uint8_t     broken;
    asm_range_t r[CRYPTO_ASM_RANGES];
} crypto_asm_t;

static inline void asm_reset(crypto_asm_t *a) {
    a->total = 0;
    a->nranges = 0;
    a->broken = 0;
}

static inline int asm_mark(crypto_asm_t *a, uint16_t lo, uint16_t hi) {
    asm_range_t out[CRYPTO_ASM_RANGES + 1];
    uint8_t i = 0, w = 0;
    while (i < a->nranges && a->r[i].hi < lo) out[w++] = a->r[i++];
    while (i < a->nranges && a->r[i].lo <= hi) {
        if (a->r[i].lo < lo) lo = a->r[i].lo;
        if (a->r[i].hi > hi) hi = a->r[i].hi;
        i++;
    }
    out[w++] = (asm_range_t){ lo, hi };
    while (i < a->nranges) out[w++] = a->r[i++];
    if (w > CRYPTO_ASM_RANGES) return -1;
    memcpy(a->r, out, w * sizeof(out[0]));
    a->nranges = w;
    return 0;
}

static inline void asm_put(crypto_asm_t *a, uint64_t off, const uint8_t *p, size_t len) {
    if (a->broken || len == 0 || off >= a->cap) return;
    if (len > a->cap - off) len = a->cap - (size_t)off;
    memcpy(a->buf + off, p, len);
    if (asm_mark(a, (uint16_t)off, (uint16_t)(off + len)) != 0) a->broken = 1;
}

static inline void asm_merge(crypto_asm_t *dst, const crypto_asm_t *src) {
    for (uint8_t i = 0; i < src->nranges; i++)
        asm_put(dst, src->r[i].lo, src->buf + src->r[i].lo,
                (size_t)(src->r[i].hi - src->r[i].lo));
    if (src->broken) dst->broken = 1;
}

static inline int asm_complete(const crypto_asm_t *a) {
    return !a->broken && a->total && a->nranges &&
           a->r[0].lo == 0 && a->r[0].hi >= a->total;
}

static inline void asm_handshake_total(crypto_asm_t *a) {
    if (a->total || !a->nranges || a->r[0].lo != 0 || a->r[0].hi < 4) return;
    uint32_t t = 4 + ((uint32_t)a->buf[1] << 16 | (uint32_t)a->buf[2] << 8 | a->buf[3]);
    if (t > a->cap) a->broken = 1;
    else a->total = (uint16_t)t;
}

#endif
