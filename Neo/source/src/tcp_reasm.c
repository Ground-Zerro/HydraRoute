#include "../include/tcp_reasm.h"
#include "../include/hrneo.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

struct tcp_reasm_entry {
    uint8_t                  in_use;
    tcp_reasm_key_t          key;
    size_t                   buf_len;
    size_t                   record_len;
    uint32_t                 expected_seq;
    int64_t                  ts_added;
    struct tcp_reasm_entry  *next;
    uint8_t                  buf[TCP_REASM_BUF_SIZE];
};

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static uint32_t key_hash(const tcp_reasm_key_t *k) {
    return fnv1a_hash((const char *)k, sizeof(*k));
}

static int key_eq(const tcp_reasm_key_t *a, const tcp_reasm_key_t *b) {
    return memcmp(a, b, sizeof(*a)) == 0;
}

static tcp_reasm_entry_t *bucket_find(tcp_reasm_t *r, const tcp_reasm_key_t *k,
                                      tcp_reasm_entry_t ***prev_link_out,
                                      int *bucket_out) {
    int b = key_hash(k) & (TCP_REASM_BUCKETS - 1);
    if (bucket_out) *bucket_out = b;
    tcp_reasm_entry_t **link = &r->buckets[b];
    while (*link) {
        if (key_eq(&(*link)->key, k)) {
            if (prev_link_out) *prev_link_out = link;
            return *link;
        }
        link = &(*link)->next;
    }
    return NULL;
}

static tcp_reasm_entry_t *pool_alloc(tcp_reasm_t *r) {
    for (int i = 0; i < r->pool_size; i++) {
        if (!r->pool[i].in_use) return &r->pool[i];
    }
    return NULL;
}

static void entry_release(tcp_reasm_t *r, tcp_reasm_entry_t **link) {
    tcp_reasm_entry_t *e = *link;
    *link = e->next;
    e->in_use = 0;
    e->next = NULL;
    e->buf_len = 0;
    r->count--;
}

static tcp_reasm_entry_t *evict_lru(tcp_reasm_t *r) {
    tcp_reasm_entry_t *oldest = NULL;
    tcp_reasm_entry_t **oldest_link = NULL;
    int64_t oldest_ts = 0;

    for (int b = 0; b < TCP_REASM_BUCKETS; b++) {
        tcp_reasm_entry_t **link = &r->buckets[b];
        while (*link) {
            if (!oldest || (*link)->ts_added < oldest_ts) {
                oldest = *link;
                oldest_ts = oldest->ts_added;
                oldest_link = link;
            }
            link = &(*link)->next;
        }
    }
    if (oldest) {
        entry_release(r, oldest_link);
        r->stat_evicted++;
    }
    return oldest;
}

int tcp_reasm_init(tcp_reasm_t *r, int max_entries, int ttl_sec) {
    memset(r, 0, sizeof(*r));
    if (max_entries <= 0 || max_entries > TCP_REASM_MAX_ENTRY)
        max_entries = TCP_REASM_MAX_ENTRY;
    if (ttl_sec <= 0) ttl_sec = TCP_REASM_DEFAULT_TTL_SEC;

    r->pool = calloc((size_t)max_entries, sizeof(tcp_reasm_entry_t));
    if (!r->pool) return -1;
    r->pool_size = max_entries;
    r->ttl_ns = (int64_t)ttl_sec * 1000000000LL;
    return 0;
}

void tcp_reasm_close(tcp_reasm_t *r) {
    free(r->pool);
    memset(r, 0, sizeof(*r));
}

int tcp_reasm_start(tcp_reasm_t *r, const tcp_reasm_key_t *k,
                    const uint8_t *payload, size_t len,
                    size_t record_len, uint32_t seq) {
    if (!r->pool) return -1;
    if (record_len > TCP_REASM_BUF_SIZE) { r->stat_too_big++; return -1; }
    if (len == 0 || len > TCP_REASM_BUF_SIZE) return -1;

    int bucket;
    tcp_reasm_entry_t **prev_link;
    tcp_reasm_entry_t *existing = bucket_find(r, k, &prev_link, &bucket);
    if (existing) entry_release(r, prev_link);

    tcp_reasm_entry_t *e = pool_alloc(r);
    if (!e) {
        if (!evict_lru(r)) return -1;
        e = pool_alloc(r);
        if (!e) return -1;
    }

    e->in_use = 1;
    e->key = *k;
    e->record_len = record_len;
    e->buf_len = len;
    e->expected_seq = seq + (uint32_t)len;
    e->ts_added = now_ns();
    memcpy(e->buf, payload, len);

    e->next = r->buckets[bucket];
    r->buckets[bucket] = e;
    r->count++;
    r->stat_started++;
    return 0;
}

int tcp_reasm_lookup(tcp_reasm_t *r, const tcp_reasm_key_t *k) {
    if (!r->pool) return 0;
    return bucket_find(r, k, NULL, NULL) != NULL;
}

int tcp_reasm_feed(tcp_reasm_t *r, const tcp_reasm_key_t *k,
                   const uint8_t *payload, size_t len, uint32_t seq) {
    if (!r->pool) return -1;
    tcp_reasm_entry_t **link = NULL;
    int bucket;
    tcp_reasm_entry_t *e = bucket_find(r, k, &link, &bucket);
    if (!e) return -1;

    int32_t diff = (int32_t)(seq - e->expected_seq);
    if (diff < 0) { r->stat_retransmit++; return 0; }
    if (diff > 0) {
        entry_release(r, link);
        r->stat_drop_gap++;
        return 0;
    }
    if (e->buf_len + len > TCP_REASM_BUF_SIZE) {
        entry_release(r, link);
        r->stat_too_big++;
        return 0;
    }
    memcpy(e->buf + e->buf_len, payload, len);
    e->buf_len += len;
    e->expected_seq = seq + (uint32_t)len;
    return 1;
}

int tcp_reasm_complete(tcp_reasm_t *r, const tcp_reasm_key_t *k) {
    if (!r->pool) return 0;
    tcp_reasm_entry_t *e = bucket_find(r, k, NULL, NULL);
    if (!e) return 0;
    return e->buf_len >= e->record_len;
}

int tcp_reasm_get(tcp_reasm_t *r, const tcp_reasm_key_t *k,
                  const uint8_t **out, size_t *out_len) {
    if (!r->pool) return -1;
    tcp_reasm_entry_t *e = bucket_find(r, k, NULL, NULL);
    if (!e) return -1;
    *out = e->buf;
    *out_len = e->buf_len;
    return 0;
}

void tcp_reasm_destroy(tcp_reasm_t *r, const tcp_reasm_key_t *k) {
    if (!r->pool) return;
    tcp_reasm_entry_t **link = NULL;
    tcp_reasm_entry_t *e = bucket_find(r, k, &link, NULL);
    if (e) {
        if (e->buf_len >= e->record_len) r->stat_completed++;
        entry_release(r, link);
    }
}

void tcp_reasm_gc(tcp_reasm_t *r) {
    if (!r->pool) return;
    int64_t now = now_ns();
    for (int b = 0; b < TCP_REASM_BUCKETS; b++) {
        tcp_reasm_entry_t **link = &r->buckets[b];
        while (*link) {
            if (now - (*link)->ts_added >= r->ttl_ns) {
                entry_release(r, link);
                r->stat_expired++;
            } else {
                link = &(*link)->next;
            }
        }
    }
}
