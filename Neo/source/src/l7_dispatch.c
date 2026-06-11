#include "../include/l7_dispatch.h"
#include "../include/probe_tls.h"
#include "../include/probe_http.h"
#include "../include/bogon.h"
#include "../include/tcp_reasm.h"
#include <string.h>
#include <netinet/in.h>

static int l7_tls_enabled  = 1;
static int l7_http_enabled = 1;
static tcp_reasm_t *g_reasm_ref;

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

static void try_tls_extract(const uint8_t *payload, int payload_len,
                            uint32_t seq,
                            const tcp_reasm_key_t *key,
                            const uint8_t *daddr, int family,
                            const l7_conn_t *conn) {
    char host[256];

    if (g_reasm_ref && tcp_reasm_lookup(g_reasm_ref, key)) {
        int rc = tcp_reasm_feed(g_reasm_ref, key, payload, (size_t)payload_len, seq);
        if (rc == 1 && tcp_reasm_complete(g_reasm_ref, key)) {
            const uint8_t *full; size_t flen;
            if (tcp_reasm_get(g_reasm_ref, key, &full, &flen) == 0 &&
                tls_extract_sni(full, flen, host, sizeof(host)) &&
                !bogon_check(daddr, family))
            {
                process_hostname_event_l7(host, L7_TLS, conn);
            }
            tcp_reasm_destroy(g_reasm_ref, key);
        }
        return;
    }

    if (!tls_quick_check(payload, (size_t)payload_len)) return;

    size_t reclen = (size_t)((payload[3] << 8) | payload[4]) + 5;
    if (reclen <= (size_t)payload_len) {
        if (tls_extract_sni(payload, (size_t)payload_len, host, sizeof(host)) &&
            !bogon_check(daddr, family))
        {
            process_hostname_event_l7(host, L7_TLS, conn);
        }
        return;
    }

    if (g_reasm_ref)
        tcp_reasm_start(g_reasm_ref, key, payload, (size_t)payload_len, reclen, seq);
}

void l7_dispatch_packet(const uint8_t *pkt, int len,
                        uint32_t mark, uint32_t ifin, uint32_t ifout,
                        void *user) {
    (void)mark; (void)ifin; (void)ifout; (void)user;

    if (len < 40) return;

    uint8_t ipver = (pkt[0] >> 4) & 0xF;
    int ip_hlen;
    uint8_t l4_proto;
    const uint8_t *saddr;
    const uint8_t *daddr;
    int dst_family;

    if (ipver == 4) {
        ip_hlen = (pkt[0] & 0xF) * 4;
        if (ip_hlen < 20 || len < ip_hlen + 20) return;
        l4_proto = pkt[9];
        saddr = pkt + 12;
        daddr = pkt + 16;
        dst_family = AF_INET;
    } else if (ipver == 6) {
        ip_hlen = 40;
        if (len < 60) return;
        l4_proto = pkt[6];
        saddr = pkt + 8;
        daddr = pkt + 24;
        dst_family = AF_INET6;
    } else {
        return;
    }

    if (l4_proto != IPPROTO_TCP) return;

    const uint8_t *tcp = pkt + ip_hlen;
    uint16_t sport = ((uint16_t)tcp[0] << 8) | tcp[1];
    uint16_t dport = ((uint16_t)tcp[2] << 8) | tcp[3];
    uint32_t seq   = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
                     ((uint32_t)tcp[6] <<  8) |  (uint32_t)tcp[7];
    uint8_t flags = tcp[13];

    if (!(flags & 0x10) || (flags & 0x02)) return;

    int tcp_hlen = ((tcp[12] >> 4) & 0xF) * 4;
    if (tcp_hlen < 20) return;
    int payload_off = ip_hlen + tcp_hlen;
    if (len <= payload_off) return;

    const uint8_t *payload = pkt + payload_off;
    int payload_len = len - payload_off;

    l7_conn_t conn;
    memset(&conn, 0, sizeof(conn));
    conn.family = (uint8_t)dst_family;
    conn.client_port = sport;
    conn.server_port = dport;
    if (dst_family == AF_INET) {
        memcpy(conn.client_ip, saddr, 4);
        memcpy(conn.server_ip, daddr, 4);
    } else {
        memcpy(conn.client_ip, saddr, 16);
        memcpy(conn.server_ip, daddr, 16);
    }

    if (dport == 443) {
        if (!l7_tls_enabled) return;
        tcp_reasm_key_t key;
        build_key(&key, dst_family, saddr, daddr, sport, dport);
        try_tls_extract(payload, payload_len, seq, &key, daddr, dst_family, &conn);
        return;
    }

    if (dport == 80) {
        if (!l7_http_enabled) return;
        if (!http_quick_check(payload, (size_t)payload_len)) return;
        char host[256];
        if (!http_extract_host(payload, (size_t)payload_len, host, sizeof(host)))
            return;
        if (bogon_check(daddr, dst_family)) return;
        process_hostname_event_l7(host, L7_HTTP, &conn);
    }
}
