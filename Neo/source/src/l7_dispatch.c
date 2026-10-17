#include "../include/l7_dispatch.h"
#include "../include/probe_tls.h"
#include "../include/probe_http.h"
#include "../include/probe_quic.h"
#include "../include/bogon.h"
#include "../include/tcp_reasm.h"
#include <string.h>
#include <netinet/in.h>

static int l7_tls_enabled  = 1;
static int l7_http_enabled = 1;
static int l7_quic_enabled = 1;
static tcp_reasm_t *g_reasm_ref;

void l7_dispatch_set_enable(int tls_enabled, int http_enabled, int quic_enabled) {
    l7_tls_enabled  = tls_enabled  ? 1 : 0;
    l7_http_enabled = http_enabled ? 1 : 0;
    l7_quic_enabled = quic_enabled ? 1 : 0;
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

static void build_quic_key(tcp_reasm_key_t *k, int family,
                           const uint8_t *saddr, const uint8_t *daddr,
                           uint16_t sport, uint16_t dport) {
    build_key(k, family, saddr, daddr, sport, dport);
    k->family |= 0x80;
}

typedef int (*stream_parse_fn)(const uint8_t *data, size_t len, char *host, size_t host_size);

static int tls_stream(const uint8_t *data, size_t len, char *host, size_t host_size) {
    if (len < 11) return tls_record_prefix(data, len) ? 0 : -1;
    if (!tls_quick_check(data, len)) return -1;
    size_t reclen = (size_t)((data[3] << 8) | data[4]) + 5;
    if (reclen > TCP_REASM_BUF_SIZE) return -1;
    if (len < reclen) return 0;
    return tls_handshake_sni(data + 5, reclen - 5, host, host_size) ? 1 : -1;
}

static int http_stream(const uint8_t *data, size_t len, char *host, size_t host_size) {
    if (!http_request_prefix(data, len)) return -1;
    if (http_extract_host(data, len, host, host_size)) return 1;
    return http_headers_end(data, len) || len >= TCP_REASM_BUF_SIZE ? -1 : 0;
}

static int stream_host(stream_parse_fn parse, const uint8_t *payload, size_t len, uint32_t seq,
                       const tcp_reasm_key_t *key, char *host, size_t host_size) {
    uint32_t base;
    crypto_asm_t *e = g_reasm_ref ? tcp_reasm_find(g_reasm_ref, key, &base) : NULL;
    if (e && seq - base >= e->cap) {
        tcp_reasm_destroy(g_reasm_ref, key);
        e = NULL;
    }
    if (!e) {
        int r = parse(payload, len, host, host_size);
        if (r != 0 || !g_reasm_ref) return r > 0;
        e = tcp_reasm_acquire(g_reasm_ref, key, seq);
        if (!e) return 0;
        base = seq;
    }
    asm_put(e, seq - base, payload, len);
    int r = e->broken ? -1 : e->r[0].lo ? 0 : parse(e->buf, e->r[0].hi, host, host_size);
    if (r != 0) tcp_reasm_destroy(g_reasm_ref, key);
    return r > 0;
}

static int quic_sni(const uint8_t *quic, int quic_len, const tcp_reasm_key_t *key,
                    char *host, size_t host_size) {
    static uint8_t local[TCP_REASM_BUF_SIZE];
    crypto_asm_t a = { .buf = local, .cap = sizeof(local) };
    if (!quic_walk_initial(quic, quic_len, &a) || !a.nranges) return 0;
    asm_handshake_total(&a);
    if (asm_complete(&a)) return tls_handshake_sni(local, a.total, host, host_size);
    if (!g_reasm_ref) return 0;

    crypto_asm_t *e = tcp_reasm_acquire(g_reasm_ref, key, 0);
    if (!e) return 0;
    asm_merge(e, &a);
    asm_handshake_total(e);
    if (!asm_complete(e)) {
        if (e->broken) tcp_reasm_destroy(g_reasm_ref, key);
        return 0;
    }
    int ok = tls_handshake_sni(e->buf, e->total, host, host_size);
    tcp_reasm_destroy(g_reasm_ref, key);
    return ok;
}

void l7_dispatch_packet(const uint8_t *pkt, int len,
                        uint32_t mark, uint32_t ifin, uint32_t ifout,
                        void *user) {
    (void)ifin; (void)ifout; (void)user;

    if (len < 28) return;

    uint8_t ipver = (pkt[0] >> 4) & 0xF;
    int ip_hlen;
    uint8_t l4_proto;
    const uint8_t *saddr;
    const uint8_t *daddr;
    int dst_family;

    if (ipver == 4) {
        ip_hlen = (pkt[0] & 0xF) * 4;
        if (ip_hlen < 20 || len < ip_hlen + 8) return;
        l4_proto = pkt[9];
        saddr = pkt + 12;
        daddr = pkt + 16;
        dst_family = AF_INET;
    } else if (ipver == 6) {
        ip_hlen = 40;
        if (len < 48) return;
        l4_proto = pkt[6];
        saddr = pkt + 8;
        daddr = pkt + 24;
        dst_family = AF_INET6;
    } else {
        return;
    }

    if (l4_proto == IPPROTO_UDP) {
        if (!l7_quic_enabled) return;
        const uint8_t *udp = pkt + ip_hlen;
        if (len < ip_hlen + 8) return;
        uint16_t sport = ((uint16_t)udp[0] << 8) | udp[1];
        uint16_t dport = ((uint16_t)udp[2] << 8) | udp[3];
        if (dport != 443) return;

        const uint8_t *quic = udp + 8;
        int quic_len = len - ip_hlen - 8;
        if (quic_len < 20) return;

        tcp_reasm_key_t key;
        build_quic_key(&key, dst_family, saddr, daddr, sport, dport);
        char host[256];
        if (!quic_sni(quic, quic_len, &key, host, sizeof(host))) return;
        if (bogon_check(daddr, dst_family)) return;

        l7_conn_t conn;
        memset(&conn, 0, sizeof(conn));
        conn.family = (uint8_t)dst_family;
        conn.proto  = IPPROTO_UDP;
        conn.mark   = mark;
        conn.client_port = sport;
        conn.server_port = dport;
        if (dst_family == AF_INET) {
            memcpy(conn.client_ip, saddr, 4);
            memcpy(conn.server_ip, daddr, 4);
        } else {
            memcpy(conn.client_ip, saddr, 16);
            memcpy(conn.server_ip, daddr, 16);
        }
        process_hostname_event_l7(host, L7_QUIC, &conn);
        return;
    }

    if (l4_proto != IPPROTO_TCP) return;
    if (len < ip_hlen + 20) return;

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
    conn.proto  = IPPROTO_TCP;
    conn.mark   = mark;
    conn.client_port = sport;
    conn.server_port = dport;
    if (dst_family == AF_INET) {
        memcpy(conn.client_ip, saddr, 4);
        memcpy(conn.server_ip, daddr, 4);
    } else {
        memcpy(conn.client_ip, saddr, 16);
        memcpy(conn.server_ip, daddr, 16);
    }

    int proto;
    stream_parse_fn parse;
    if (dport == 443 && l7_tls_enabled) {
        proto = L7_TLS;
        parse = tls_stream;
    } else if (dport == 80 && l7_http_enabled) {
        proto = L7_HTTP;
        parse = http_stream;
    } else {
        return;
    }

    tcp_reasm_key_t key;
    build_key(&key, dst_family, saddr, daddr, sport, dport);
    char host[256];
    if (stream_host(parse, payload, (size_t)payload_len, seq, &key, host, sizeof(host)) &&
        !bogon_check(daddr, dst_family))
        process_hostname_event_l7(host, proto, &conn);
}
