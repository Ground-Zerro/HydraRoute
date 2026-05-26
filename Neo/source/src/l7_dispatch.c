#include "../include/l7_dispatch.h"
#include "../include/probe_tls.h"
#include "../include/probe_http.h"
#include "../include/bogon.h"
#include "../include/tcp_reasm.h"
#include "../include/log.h"
#include <string.h>
#include <netinet/in.h>

static int l7_tls_enabled  = 1;
static int l7_http_enabled = 1;
static tcp_reasm_t *g_reasm_ref;

static uint64_t stat_too_short;
static uint64_t stat_malformed;
static uint64_t stat_not_tcp;
static uint64_t stat_wrong_flags;
static uint64_t stat_empty;
static uint64_t stat_wrong_port;
static uint64_t stat_not_tls_ch;
static uint64_t stat_tls_no_sni;
static uint64_t stat_tls_matched;
static uint64_t stat_not_http;
static uint64_t stat_http_no_host;
static uint64_t stat_http_matched;
static uint64_t stat_bogon;
static uint64_t stat_disabled;
static uint64_t stat_reasm_started;
static uint64_t stat_reasm_completed;

void l7_dispatch_set_enable(int tls_enabled, int http_enabled) {
    l7_tls_enabled  = tls_enabled  ? 1 : 0;
    l7_http_enabled = http_enabled ? 1 : 0;
}

void l7_dispatch_set_reasm(struct tcp_reasm *reasm) {
    g_reasm_ref = (tcp_reasm_t *)reasm;
}

static void build_key(tcp_reasm_key_t *k, int family,
                      const uint8_t *saddr, const uint8_t *daddr,
                      uint16_t sport, uint16_t dport) {
    memset(k, 0, sizeof(*k));
    k->family = (uint8_t)family;
    if (family == AF_INET) {
        memcpy(k->src_ip, saddr, 4);
        memcpy(k->dst_ip, daddr, 4);
    } else {
        memcpy(k->src_ip, saddr, 16);
        memcpy(k->dst_ip, daddr, 16);
    }
    k->src_port = sport;
    k->dst_port = dport;
}

static int try_tls_extract(const uint8_t *payload, int payload_len,
                           uint32_t seq,
                           const tcp_reasm_key_t *key,
                           const uint8_t *daddr, int family) {
    char host[256];

    if (g_reasm_ref && tcp_reasm_lookup(g_reasm_ref, key)) {
        int rc = tcp_reasm_feed(g_reasm_ref, key, payload, (size_t)payload_len, seq);
        if (rc == 1 && tcp_reasm_complete(g_reasm_ref, key)) {
            const uint8_t *full; size_t flen;
            if (tcp_reasm_get(g_reasm_ref, key, &full, &flen) == 0 &&
                tls_extract_sni(full, flen, host, sizeof(host)))
            {
                stat_reasm_completed++;
                if (bogon_check(daddr, family)) { stat_bogon++; }
                else process_hostname_event_l7(host, L7_TLS, daddr, family);
            }
            tcp_reasm_destroy(g_reasm_ref, key);
        }
        return 1;
    }

    if (!tls_quick_check(payload, (size_t)payload_len)) { stat_not_tls_ch++; return 0; }

    size_t reclen = (size_t)((payload[3] << 8) | payload[4]) + 5;
    if (reclen <= (size_t)payload_len) {
        if (!tls_extract_sni(payload, (size_t)payload_len, host, sizeof(host))) {
            stat_tls_no_sni++; return 0;
        }
        stat_tls_matched++;
        if (bogon_check(daddr, family)) { stat_bogon++; return 0; }
        process_hostname_event_l7(host, L7_TLS, daddr, family);
        return 1;
    }

    if (g_reasm_ref &&
        tcp_reasm_start(g_reasm_ref, key, payload, (size_t)payload_len, reclen, seq) == 0)
    {
        stat_reasm_started++;
    } else {
        stat_tls_no_sni++;
    }
    return 0;
}

void l7_dispatch_packet(const uint8_t *pkt, int len,
                        uint32_t mark, uint32_t ifin, uint32_t ifout,
                        void *user) {
    (void)mark; (void)ifin; (void)ifout; (void)user;

    if (len < 40) { stat_too_short++; return; }

    uint8_t ipver = (pkt[0] >> 4) & 0xF;
    int ip_hlen;
    uint8_t l4_proto;
    const uint8_t *saddr;
    const uint8_t *daddr;
    int dst_family;

    if (ipver == 4) {
        ip_hlen = (pkt[0] & 0xF) * 4;
        if (ip_hlen < 20 || len < ip_hlen + 20) { stat_malformed++; return; }
        l4_proto = pkt[9];
        saddr = pkt + 12;
        daddr = pkt + 16;
        dst_family = AF_INET;
    } else if (ipver == 6) {
        ip_hlen = 40;
        if (len < 60) { stat_malformed++; return; }
        l4_proto = pkt[6];
        saddr = pkt + 8;
        daddr = pkt + 24;
        dst_family = AF_INET6;
    } else {
        stat_malformed++; return;
    }

    if (l4_proto != IPPROTO_TCP) { stat_not_tcp++; return; }

    const uint8_t *tcp = pkt + ip_hlen;
    uint16_t sport = ((uint16_t)tcp[0] << 8) | tcp[1];
    uint16_t dport = ((uint16_t)tcp[2] << 8) | tcp[3];
    uint32_t seq   = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
                     ((uint32_t)tcp[6] <<  8) |  (uint32_t)tcp[7];
    uint8_t flags = tcp[13];

    if (!(flags & 0x10) || (flags & 0x02)) { stat_wrong_flags++; return; }

    int tcp_hlen = ((tcp[12] >> 4) & 0xF) * 4;
    if (tcp_hlen < 20) { stat_malformed++; return; }
    int payload_off = ip_hlen + tcp_hlen;
    if (len <= payload_off) { stat_empty++; return; }

    const uint8_t *payload = pkt + payload_off;
    int payload_len = len - payload_off;

    if (dport == 443) {
        if (!l7_tls_enabled) { stat_disabled++; return; }
        tcp_reasm_key_t key;
        build_key(&key, dst_family, saddr, daddr, sport, dport);
        try_tls_extract(payload, payload_len, seq, &key, daddr, dst_family);
        return;
    }

    if (dport == 80) {
        if (!l7_http_enabled) { stat_disabled++; return; }
        if (!http_quick_check(payload, (size_t)payload_len)) { stat_not_http++; return; }
        char host[256];
        if (!http_extract_host(payload, (size_t)payload_len, host, sizeof(host))) {
            stat_http_no_host++; return;
        }
        stat_http_matched++;
        if (bogon_check(daddr, dst_family)) { stat_bogon++; return; }
        process_hostname_event_l7(host, L7_HTTP, daddr, dst_family);
        return;
    }

    stat_wrong_port++;
}

void l7_dispatch_dump_stats(void) {
    LOG_INFO("L7 dispatch stats: too_short=%llu malformed=%llu not_tcp=%llu wrong_flags=%llu empty=%llu wrong_port=%llu",
             (unsigned long long)stat_too_short,
             (unsigned long long)stat_malformed,
             (unsigned long long)stat_not_tcp,
             (unsigned long long)stat_wrong_flags,
             (unsigned long long)stat_empty,
             (unsigned long long)stat_wrong_port);
    LOG_INFO("L7 dispatch stats: not_tls=%llu tls_no_sni=%llu tls_matched=%llu not_http=%llu http_no_host=%llu http_matched=%llu bogon=%llu disabled=%llu",
             (unsigned long long)stat_not_tls_ch,
             (unsigned long long)stat_tls_no_sni,
             (unsigned long long)stat_tls_matched,
             (unsigned long long)stat_not_http,
             (unsigned long long)stat_http_no_host,
             (unsigned long long)stat_http_matched,
             (unsigned long long)stat_bogon,
             (unsigned long long)stat_disabled);
    LOG_INFO("L7 reasm stats: started=%llu completed=%llu",
             (unsigned long long)stat_reasm_started,
             (unsigned long long)stat_reasm_completed);
}
