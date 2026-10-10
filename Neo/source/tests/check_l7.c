#include "pkt.h"
#include "../include/l7_dispatch.h"
#include "../include/probe_quic.h"
#include "../include/probe_tls.h"
#include "../include/probe_http.h"
#include "../include/quic_crypto.h"
#include "../include/tcp_reasm.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static char g_host[256];
static int g_proto;
static int g_events;

void process_hostname_event_l7(const char *host, int proto, const l7_conn_t *conn) {
    (void)conn;
    snprintf(g_host, sizeof(g_host), "%s", host);
    g_proto = proto;
    g_events++;
}

static void reset_events(void) {
    g_host[0] = 0;
    g_proto = 0;
    g_events = 0;
}

static uint8_t *guarded(const uint8_t *data, size_t len) {
    long pg = sysconf(_SC_PAGESIZE);
    uint8_t *m = mmap(NULL, (size_t)pg * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(m != MAP_FAILED);
    assert(mprotect(m + pg, (size_t)pg, PROT_NONE) == 0);
    uint8_t *p = m + pg - len;
    memcpy(p, data, len);
    return p;
}

static void check_varint_wrap(void) {
    static const uint8_t payload_wrap[20] = {
        0xC0, 0x00, 0x00, 0x00, 0x01, 0x04, 1, 2, 3, 4, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xEC
    };
    uint8_t buf[TCP_REASM_BUF_SIZE];
    crypto_asm_t a = { .buf = buf, .cap = sizeof(buf) };
    assert(quic_walk_initial(guarded(payload_wrap, sizeof(payload_wrap)),
                             sizeof(payload_wrap), &a) == 0);
}

static const uint8_t RFC_DCID[8] = { 0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08 };

static void check_rfc_keys(void) {
    static const uint8_t V1_KEY[16] = { 0x1f,0x36,0x96,0x13,0xdd,0x76,0xd5,0x46,0x77,0x30,0xef,0xcb,0xe3,0xb1,0xa2,0x2d };
    static const uint8_t V1_IV[12]  = { 0xfa,0x04,0x4b,0x2f,0x42,0xa3,0xfd,0x3b,0x46,0xfb,0x25,0x5c };
    static const uint8_t V1_HP[16]  = { 0x9f,0x50,0x44,0x9e,0x04,0xa0,0xe8,0x10,0x28,0x3a,0x1e,0x99,0x33,0xad,0xed,0xd2 };
    static const uint8_t V2_KEY[16] = { 0x8b,0x1a,0x0b,0xc1,0x21,0x28,0x42,0x90,0xa2,0x9e,0x09,0x71,0xb5,0xcd,0x04,0x5d };
    static const uint8_t V2_IV[12]  = { 0x91,0xf7,0x3e,0x23,0x51,0xd8,0xfa,0x91,0x66,0x0e,0x90,0x9f };
    static const uint8_t V2_HP[16]  = { 0x45,0xb9,0x5e,0x15,0x23,0x5d,0x6f,0x45,0xa6,0xb1,0x9c,0xbc,0xb0,0x29,0x4b,0xa9 };
    quic_keys_t k;
    quic_derive(0, RFC_DCID, sizeof(RFC_DCID), &k);
    assert(!memcmp(k.key, V1_KEY, 16) && !memcmp(k.iv, V1_IV, 12) && !memcmp(k.hp, V1_HP, 16));
    quic_derive(1, RFC_DCID, sizeof(RFC_DCID), &k);
    assert(!memcmp(k.key, V2_KEY, 16) && !memcmp(k.iv, V2_IV, 12) && !memcmp(k.hp, V2_HP, 16));
}

static const uint8_t SRC[4] = { 192, 168, 1, 10 };
static const uint8_t DST[4] = { 142, 250, 1, 1 };

static uint8_t g_pkt[TCP_REASM_BUF_SIZE];

static void send_quic(uint16_t sport, int v2, const uint8_t *ch, const frag_t *fr, int nfr) {
    uint8_t plain[1440], dgram[1500];
    size_t pl = quic_pad(plain, quic_crypto_frames(plain, ch, fr, nfr));
    size_t n = quic_protect(dgram, v2, plain, pl);
    size_t len = ip_udp(g_pkt, 0, SRC, DST, sport, 443, dgram, n);
    l7_dispatch_packet(g_pkt, (int)len, 0, 0, 0, NULL);
}

static void expect(const char *host, int proto) {
    assert(g_events == 1);
    assert(g_proto == proto);
    assert(strcmp(g_host, host) == 0);
    reset_events();
}

static void check_quic(void) {
    uint8_t ch[4096];
    size_t n = client_hello(ch, "www.youtube.com", 100);

    reset_events();
    send_quic(50001, 0, ch, (frag_t[]){ { 0, n } }, 1);
    expect("www.youtube.com", L7_QUIC);

    send_quic(50002, 0, ch, (frag_t[]){ { 0, 60 }, { 60, n - 60 } }, 2);
    expect("www.youtube.com", L7_QUIC);

    send_quic(50003, 0, ch, (frag_t[]){ { 90, n - 90 }, { 30, 60 }, { 0, 30 } }, 3);
    expect("www.youtube.com", L7_QUIC);

    send_quic(50004, 1, ch, (frag_t[]){ { 0, n } }, 1);
    expect("www.youtube.com", L7_QUIC);

    size_t big = client_hello(ch, "chatgpt.com", 1800);
    send_quic(50005, 0, ch, (frag_t[]){ { 1100, big - 1100 }, { 0, 200 } }, 2);
    assert(g_events == 0);
    send_quic(50005, 0, ch, (frag_t[]){ { 700, 400 } }, 1);
    assert(g_events == 0);
    send_quic(50005, 0, ch, (frag_t[]){ { 200, 500 } }, 1);
    expect("chatgpt.com", L7_QUIC);
}

static void send_tcp(uint16_t dport, uint32_t seq, const uint8_t *data, size_t len) {
    size_t n = ip_tcp(g_pkt, 0, SRC, DST, 0xC001, dport, seq, 0x18, data, len);
    l7_dispatch_packet(g_pkt, (int)n, 0, 0, 0, NULL);
}

static void check_tcp(void) {
    uint8_t rec[4096];
    size_t n = tls_record(rec, "Example.COM", 50);

    reset_events();
    send_tcp(443, 1000, rec, n);
    expect("example.com", L7_TLS);

    n = tls_record(rec, "reorder.example.com", 2000);
    uint32_t s = 0xFFFFFF00u;
    send_tcp(443, s, rec, 700);
    send_tcp(443, s + 1400, rec + 1400, n - 1400);
    assert(g_events == 0);
    send_tcp(443, s + 700, rec + 700, 700);
    expect("reorder.example.com", L7_TLS);

    send_tcp(443, 5000, rec, 700);
    send_tcp(443, 5000 + 700, rec + 700, 700);
    send_tcp(443, 5000 + 700, rec + 700, 700);
    send_tcp(443, 5000 + 1400, rec + 1400, n - 1400);
    expect("reorder.example.com", L7_TLS);
}

static void check_short_first(void) {
    uint8_t rec[4096];
    size_t n = tls_record(rec, "split.example.com", 100);
    reset_events();

    send_tcp(443, 9000, rec, 1);
    send_tcp(443, 9001, rec + 1, n - 1);
    expect("split.example.com", L7_TLS);

    send_tcp(443, 9100, rec, 2);
    send_tcp(443, 9102, rec + 2, 3);
    assert(g_events == 0);
    send_tcp(443, 9105, rec + 5, n - 5);
    expect("split.example.com", L7_TLS);

    n = tls_record(rec, "split.example.com", 2000);
    send_tcp(443, 9300, rec, 1);
    send_tcp(443, 9300 + 1400, rec + 1400, n - 1400);
    send_tcp(443, 9300 + 1, rec + 1, 1399);
    expect("split.example.com", L7_TLS);

    static const uint8_t junk[] = { 0x16, 0x99, 0x01 };
    send_tcp(443, 9500, junk, 1);
    send_tcp(443, 9501, junk + 1, 2);
    send_tcp(443, 9503, rec + 3, 100);
    assert(g_events == 0);

    static const char req[] = "GET / HTTP/1.1\r\nHost: claude.ai\r\nAccept: */*\r\n\r\n";
    size_t rl = sizeof(req) - 1, cut = strlen("GET / HTTP/1.1\r\nHost: clau");
    send_tcp(80, 100, (const uint8_t *)req, 1);
    send_tcp(80, 101, (const uint8_t *)req + 1, rl - 1);
    expect("claude.ai", L7_HTTP);

    send_tcp(80, 200, (const uint8_t *)req, cut);
    assert(g_events == 0);
    send_tcp(80, 200 + (uint32_t)cut, (const uint8_t *)req + cut, rl - cut);
    expect("claude.ai", L7_HTTP);

    static const char nohost[] = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
    static const char late[] = "Host: claude.ai\r\n\r\n";
    send_tcp(80, 300, (const uint8_t *)nohost, 5);
    send_tcp(80, 305, (const uint8_t *)nohost + 5, sizeof(nohost) - 6);
    send_tcp(80, 300 + sizeof(nohost) - 1, (const uint8_t *)late, sizeof(late) - 1);
    assert(g_events == 0);
}

static void check_names(void) {
    char longname[300];
    memset(longname, 'a', 250);
    strcpy(longname + 250, ".youtube.com.evil.example");
    uint8_t rec[4096];
    char host[256];

    size_t n = tls_record(rec, longname, 10);
    assert(!tls_handshake_sni(rec + 5, n - 5, host, sizeof(host)));
    n = tls_record(rec, "bad host.com", 10);
    assert(!tls_handshake_sni(rec + 5, n - 5, host, sizeof(host)));
    n = tls_record(rec, "ok-host_1.example.", 10);
    assert(tls_handshake_sni(rec + 5, n - 5, host, sizeof(host)));
    assert(strcmp(host, "ok-host_1.example") == 0);

    static const char req[] = "GET / HTTP/1.1\r\nHost: WWW.Example.org:8080\r\n\r\n";
    assert(http_extract_host((const uint8_t *)req, sizeof(req) - 1, host, sizeof(host)));
    assert(strcmp(host, "www.example.org") == 0);
    static const char v6[] = "GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n";
    assert(!http_extract_host((const uint8_t *)v6, sizeof(v6) - 1, host, sizeof(host)));
    static const char cut[] = "GET / HTTP/1.1\r\nHost: www.youtube.co";
    assert(!http_extract_host((const uint8_t *)cut, sizeof(cut) - 1, host, sizeof(host)));

    char req_long[400];
    int rl = snprintf(req_long, sizeof(req_long), "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", longname);
    assert(!http_extract_host((const uint8_t *)req_long, (size_t)rl, host, sizeof(host)));
}

int main(void) {
    static tcp_reasm_t reasm;
    assert(tcp_reasm_init(&reasm, 8, 5) == 0);
    l7_dispatch_set_reasm(&reasm);

    check_varint_wrap();
    check_rfc_keys();
    check_quic();
    check_tcp();
    check_short_first();
    check_names();

    tcp_reasm_close(&reasm);
    puts("check_l7: OK");
    return 0;
}
