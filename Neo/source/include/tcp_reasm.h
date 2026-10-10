#ifndef TCP_REASM_H
#define TCP_REASM_H

#include <stdint.h>
#include <stddef.h>
#include "crypto_asm.h"

#define TCP_REASM_BUCKETS    64
#define TCP_REASM_MAX_ENTRY  256
#define TCP_REASM_BUF_SIZE   (16 * 1024)
#define TCP_REASM_DEFAULT_TTL_SEC 5

typedef struct {
    uint8_t  family;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
} tcp_reasm_key_t;

typedef struct tcp_reasm_entry tcp_reasm_entry_t;

typedef struct tcp_reasm {
    tcp_reasm_entry_t *pool;
    int                pool_size;
    int64_t            ttl_ns;
    tcp_reasm_entry_t *buckets[TCP_REASM_BUCKETS];
} tcp_reasm_t;

int  tcp_reasm_init   (tcp_reasm_t *r, int max_entries, int ttl_sec);
void tcp_reasm_close  (tcp_reasm_t *r);

crypto_asm_t *tcp_reasm_find   (tcp_reasm_t *r, const tcp_reasm_key_t *k, uint32_t *base_seq);
crypto_asm_t *tcp_reasm_acquire(tcp_reasm_t *r, const tcp_reasm_key_t *k, uint32_t base_seq);

void tcp_reasm_destroy(tcp_reasm_t *r, const tcp_reasm_key_t *k);

void tcp_reasm_gc     (tcp_reasm_t *r);

#endif
