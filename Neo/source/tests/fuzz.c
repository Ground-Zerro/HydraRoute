#include "pkt.h"
#include "../include/l7_dispatch.h"
#include "../include/dns.h"
#include "../include/tcp_reasm.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#define FUZZ_REASM_ENTRIES 32
#define FUZZ_REASM_RESET   64
#define FUZZ_WATCHDOG_SEC  20
#define FUZZ_SEED_RUNS     256
#define PKT_MAX            (TCP_REASM_BUF_SIZE + 64)

enum { K_TLS, K_HTTP, K_QUIC, K_DNS, K_KINDS };
static const char *const KIND_NAME[K_KINDS] = { "tls", "http", "quic", "dns" };

static const char *const SNI[] = { "chatgpt.com", "claude.ai", "www.youtube.com", "a.b.c.example.org" };
static const char *const HTTP_REQ[] = {
    "GET / HTTP/1.1\r\nHost: claude.ai\r\nUser-Agent: fuzz\r\nAccept: */*\r\n\r\n",
    "POST /x HTTP/1.0\r\nhost: CHATGPT.COM:8080\r\nContent-Length: 0\r\n\r\n",
};
static const char *const CNAME[] = { "telegra.ph", "edge.example.net", "a.b.c.d.e.f.example.org" };
static const uint16_t MAGIC16[] = { 0, 1, 2, 0x3f, 0x40, 0x7f, 0x80, 0xc0, 0xff, 0x100,
                                    0x3fff, 0x4000, 0x7fff, 0x8000, 0xfffe, 0xffff };

static const uint8_t SRC4[4] = { 192, 168, 2, 210 };
static uint8_t DST4[4] = { 198, 51, 100, 20 };
static const uint8_t SRC6[16] = { 0x20, 0x01, 0x0d, 0xb8, [15] = 0x10 };
static const uint8_t DST6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 1, [15] = 0x20 };

typedef void (*sink_fn)(int kind, uint8_t *pkt, size_t len);

static uint64_t g_rng, g_seed, g_iter;
static int g_kind, g_mutate = 1, g_emit;
static const char *g_name;
static long g_runs[K_KINDS], g_hits[K_KINDS];
static tcp_reasm_t g_reasm;
static uint8_t g_pkt[PKT_MAX];

static uint32_t rnd(uint32_t n) {
    g_rng ^= g_rng >> 12; g_rng ^= g_rng << 25; g_rng ^= g_rng >> 27;
    return n ? (uint32_t)((g_rng * 0x2545F4914F6CDD1DULL) >> 32) % n : 0;
}

static void report(void) {
    char msg[128];
    int n = snprintf(msg, sizeof(msg), "fuzz: FAIL seed=%llu iter=%llu kind=%s\n",
                     (unsigned long long)g_seed, (unsigned long long)g_iter, KIND_NAME[g_kind]);
    if (write(STDERR_FILENO, msg, (size_t)n) < 0) _exit(3);
}

static void on_fatal(int sig) {
    report();
    signal(sig, SIG_DFL);
    raise(sig);
}

#ifdef __SANITIZE_ADDRESS__
void __sanitizer_set_death_callback(void (*cb)(void));
#endif

void process_hostname_event_l7(const char *host, int proto, const l7_conn_t *conn) {
    size_t n = strlen(host);
    if (n == 0 || n > 253 || proto < L7_TLS || proto > L7_QUIC || !conn) abort();
    for (size_t i = 0; i < n; i++) {
        char c = host[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_'))
            abort();
    }
    g_hits[g_kind]++;
}

static void mutate(uint8_t *b, size_t *n, size_t cap) {
    for (int ops = 1 + (int)rnd(6); ops > 0; ops--) {
        size_t len = *n;
        if (len < 2) { b[0] = (uint8_t)rnd(256); b[1] = (uint8_t)rnd(256); *n = 2; continue; }
        size_t at = rnd((uint32_t)len), k;
        uint16_t v;
        switch (rnd(7)) {
        case 0:
            b[at] ^= (uint8_t)(1u << rnd(8));
            break;
        case 1:
            b[at] = (uint8_t)MAGIC16[rnd(sizeof(MAGIC16) / 2)];
            break;
        case 2:
            if (at + 1 >= len) break;
            v = rnd(2) ? MAGIC16[rnd(sizeof(MAGIC16) / 2)] : (uint16_t)(len - at + rnd(5) - 2);
            b[at] = (uint8_t)(v >> 8); b[at + 1] = (uint8_t)v;
            break;
        case 3:
            k = 1 + rnd((uint32_t)(len - at));
            memmove(b + at, b + at + k, len - at - k);
            *n = len - k;
            break;
        case 4:
            k = 1 + rnd(32);
            if (len + k > cap) break;
            memmove(b + at + k, b + at, len - at);
            for (size_t i = 0; i < k; i++) b[at + i] = (uint8_t)rnd(256);
            *n = len + k;
            break;
        case 5: {
            size_t src = rnd((uint32_t)len), hi = src > at ? src : at;
            memmove(b + at, b + src, 1 + rnd((uint32_t)(len - hi)));
            break;
        }
        default:
            *n = at;
            break;
        }
    }
}

static int maybe(uint32_t one_in) {
    return g_mutate && rnd(one_in) == 0;
}

static void mutate_header(uint8_t *pkt, size_t *len) {
    size_t span = *len < 60 ? *len : 60;
    for (int k = 1 + (int)rnd(4); k > 0; k--) pkt[rnd((uint32_t)span)] ^= (uint8_t)(1u << rnd(8));
    if (rnd(4) == 0) *len = rnd((uint32_t)*len + 1);
}

static void parse(int kind, const uint8_t *pkt, size_t len) {
    if (kind != K_DNS) {
        l7_dispatch_packet(pkt, (int)len, 0, 0, 0, NULL);
        return;
    }
    static dns_result_t res;
    int dns_len;
    const uint8_t *dns = extract_dns_payload(pkt, (int)len, &dns_len);
    if (!dns || dns_parse_response(dns, dns_len, &res) != 0) return;
    if (res.answer_count < 0 || res.answer_count > DNS_MAX_ANSWERS ||
        res.cname_count < 0 || res.cname_count > DNS_MAX_CNAMES)
        abort();
    for (int i = 0; i < res.answer_count; i++)
        if (!memchr(res.answers[i].domain, 0, sizeof(res.answers[i].domain)) ||
            (res.answers[i].family != AF_INET && res.answers[i].family != AF_INET6))
            abort();
    for (int i = 0; i < res.cname_count; i++)
        if (!memchr(res.cnames[i].source, 0, sizeof(res.cnames[i].source)) ||
            !memchr(res.cnames[i].target, 0, sizeof(res.cnames[i].target)))
            abort();
    dns_result_repeat(&res, (uint32_t)g_iter);
    if (res.answer_count > 0) g_hits[K_DNS]++;
}

static void dispatch_sink(int kind, uint8_t *pkt, size_t len) {
    if (maybe(8)) mutate_header(pkt, &len);
    uint8_t *exact = malloc(len ? len : 1);
    if (!exact) abort();
    memcpy(exact, pkt, len);
    parse(kind, exact, len);
    free(exact);
}

static uint16_t csum_add(uint32_t sum, const uint8_t *p, size_t n) {
    for (size_t i = 0; i + 1 < n; i += 2) sum += (uint32_t)p[i] << 8 | p[i + 1];
    if (n & 1) sum += (uint32_t)p[n - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)sum;
}

static void emit_sink(int kind, uint8_t *pkt, size_t len) {
    (void)kind;
    size_t l4 = len - 20;
    uint8_t *t = pkt + 20;
    int off = pkt[9] == 6 ? 16 : 6;
    uint32_t sum = csum_add(0, pkt + 12, 8) + pkt[9] + (uint32_t)l4;
    t[off] = t[off + 1] = 0;
    uint16_t c = (uint16_t)~csum_add(sum, t, l4);
    if (pkt[9] == 17 && c == 0) c = 0xFFFF;
    t[off] = (uint8_t)(c >> 8); t[off + 1] = (uint8_t)c;
    pkt[10] = pkt[11] = 0;
    c = (uint16_t)~csum_add(0, pkt, 20);
    pkt[10] = (uint8_t)(c >> 8); pkt[11] = (uint8_t)c;
    uint8_t hdr[2] = { (uint8_t)(len >> 8), (uint8_t)len };
    if (fwrite(hdr, 1, 2, stdout) != 2 || fwrite(pkt, 1, len, stdout) != len) exit(1);
}

static void shuffle(size_t *idx, size_t n) {
    for (size_t i = n; i > 1; i--) {
        size_t j = rnd((uint32_t)i), t = idx[i - 1];
        idx[i - 1] = idx[j]; idx[j] = t;
    }
}

static void tcp_flow(sink_fn sink, int kind, uint16_t dport, const uint8_t *data, size_t n) {
    int v6 = !g_emit && rnd(4) == 0;
    const uint8_t *src = v6 ? SRC6 : SRC4, *dst = v6 ? DST6 : DST4;
    uint16_t sport = (uint16_t)(20000 + rnd(40000));
    uint32_t seq = (uint32_t)rnd(0xFFFFFFFFu);
    if (g_emit)
        for (int i = 0; i < 2; i++)
            sink(kind, g_pkt, ip_tcp(g_pkt, 0, src, dst, sport, dport, seq, 0x10, data, 0));
    size_t cuts[8], idx[8], nseg = 1 + (n > 1400 ? n / 1400 : 0) + rnd(3);
    if (nseg > 8) nseg = 8;
    cuts[0] = 0;
    for (size_t i = 1; i < nseg; i++)
        cuts[i] = g_emit ? n * i / nseg : 1 + rnd((uint32_t)n);
    for (size_t i = 1; i < nseg; i++)
        for (size_t j = i; j > 1 && cuts[j] < cuts[j - 1]; j--) { size_t t = cuts[j]; cuts[j] = cuts[j - 1]; cuts[j - 1] = t; }
    for (size_t i = 0; i < nseg; i++) idx[i] = i;
    if (!g_emit && maybe(4)) shuffle(idx, nseg);
    for (size_t k = 0; k < nseg; k++) {
        size_t i = idx[k], end = i + 1 < nseg ? cuts[i + 1] : n;
        if (end <= cuts[i]) continue;
        size_t len = ip_tcp(g_pkt, v6, src, dst, sport, dport, seq + (uint32_t)cuts[i], 0x18,
                            data + cuts[i], end - cuts[i]);
        sink(kind, g_pkt, len);
        if (!g_emit && maybe(16)) sink(kind, g_pkt, len);
    }
}

static void case_tls(sink_fn sink) {
    static uint8_t rec[8192];
    size_t pad = rnd(4) ? rnd(256) : 1400 + rnd(2400);
    g_name = SNI[rnd(4)];
    size_t n = tls_record(rec, g_name, pad);
    if (g_mutate && rnd(8)) mutate(rec, &n, sizeof(rec));
    tcp_flow(sink, K_TLS, 443, rec, n);
}

static void case_http(sink_fn sink) {
    uint8_t req[512];
    const char *seed = HTTP_REQ[rnd(2)];
    g_name = seed == HTTP_REQ[0] ? "claude.ai" : "chatgpt.com";
    size_t n = strlen(seed);
    memcpy(req, seed, n);
    if (g_mutate && rnd(8)) mutate(req, &n, sizeof(req));
    tcp_flow(sink, K_HTTP, 80, req, n);
}

static void case_quic(sink_fn sink) {
    static uint8_t ch[4096], plain[2048], dgram[2112];
    g_name = SNI[rnd(4)];
    size_t chn = client_hello(ch, g_name, rnd(3) ? rnd(300) : 1000 + rnd(800));
    size_t ndg = chn > 1000 ? 2 + rnd(2) : 1 + rnd(2), bounds[4] = { 0 }, order[4];
    for (size_t i = 1; i < ndg; i++) bounds[i] = chn * i / ndg;
    bounds[ndg] = chn;
    for (size_t i = 0; i < ndg; i++) order[i] = i;
    if (!g_emit && maybe(4)) shuffle(order, ndg);
    int v6 = !g_emit && rnd(4) == 0, v2 = rnd(4) == 0;
    uint16_t sport = (uint16_t)(20000 + rnd(40000));
    for (size_t d = 0; d < ndg; d++) {
        size_t lo = bounds[order[d]], hi = bounds[order[d] + 1], nfr = 1 + rnd(3), fidx[3];
        frag_t fr[3];
        for (size_t f = 0; f < nfr; f++) {
            fr[f].off = lo + (hi - lo) * f / nfr;
            fr[f].len = lo + (hi - lo) * (f + 1) / nfr - fr[f].off;
            fidx[f] = f;
        }
        shuffle(fidx, nfr);
        frag_t sorted[3];
        for (size_t f = 0; f < nfr; f++) sorted[f] = fr[fidx[f]];
        size_t pl = quic_crypto_frames(plain, ch, sorted, (int)nfr);
        if (maybe(2)) mutate(plain, &pl, g_emit ? 1400 : sizeof(plain) - 64);
        pl = quic_pad(plain, pl);
        size_t n = quic_protect(dgram, v2, plain, pl);
        if (!g_emit && maybe(4)) mutate(dgram, &n, sizeof(dgram));
        sink(K_QUIC, g_pkt, ip_udp(g_pkt, v6, v6 ? SRC6 : SRC4, v6 ? DST6 : DST4, sport, 443, dgram, n));
    }
}

static void case_dns(sink_fn sink) {
    pkt_t p;
    int na = 1 + (int)rnd(6);
    dns_header(&p, (uint16_t)rnd(65536), (uint16_t)(na + 1));
    size_t target = p.n + 12;
    g_name = CNAME[rnd(3)];
    add_cname(&p, 300, g_name);
    for (int i = 0; i < na; i++) {
        if (rnd(3)) {
            add_a(&p, (uint16_t)(0xC000 | target), 60, (uint8_t)(10 + i));
            continue;
        }
        put16(&p, (uint16_t)(0xC000 | target));
        rr_head(&p, 28, 60);
        put16(&p, 16);
        for (int k = 0; k < 16; k++) put8(&p, (uint8_t)(k == 15 ? i : 0x20));
    }
    if (g_mutate && rnd(8)) mutate(p.b, &p.n, sizeof(p.b) - 64);
    int v6 = !g_emit && rnd(4) == 0;
    const uint8_t *src = g_emit ? SRC4 : v6 ? DST6 : DST4, *dst = g_emit ? DST4 : v6 ? SRC6 : SRC4;
    sink(K_DNS, g_pkt, ip_udp(g_pkt, v6, src, dst, 53, (uint16_t)(1024 + rnd(60000)), p.b, p.n));
}

static void (*const CASES[K_KINDS])(sink_fn) = { case_tls, case_http, case_quic, case_dns };

static void run_one(sink_fn sink, uint64_t iter) {
    g_iter = iter;
    g_rng = (g_seed ^ (iter * 0x9E3779B97F4A7C15ULL)) | 1;
    for (int i = 0; i < 4; i++) rnd(0);
    g_kind = (int)rnd(K_KINDS);
    g_runs[g_kind]++;
    if (g_emit) DST4[3] = (uint8_t)(20 + iter % 200);
    CASES[g_kind](sink);
    if (g_emit) fprintf(stderr, "case %llu %s %s 198.51.100.%u\n", (unsigned long long)iter, KIND_NAME[g_kind], g_name, DST4[3]);
}

static void reasm_reset(void) {
    tcp_reasm_close(&g_reasm);
    if (tcp_reasm_init(&g_reasm, FUZZ_REASM_ENTRIES, 1) != 0) abort();
    l7_dispatch_set_reasm(&g_reasm);
}

static void seed_check(void) {
    g_mutate = 0;
    for (uint64_t i = 0; i < FUZZ_SEED_RUNS; i++) {
        reasm_reset();
        run_one(dispatch_sink, i);
    }
    for (int k = 0; k < K_KINDS; k++) {
        if (g_hits[k] != g_runs[k]) {
            fprintf(stderr, "fuzz: seed %s: %ld of %ld recognised\n", KIND_NAME[k], g_hits[k], g_runs[k]);
            exit(2);
        }
        g_runs[k] = g_hits[k] = 0;
    }
    g_mutate = 1;
}

int main(int argc, char **argv) {
    if (argc > 2 && !strcmp(argv[1], "emit")) {
        g_emit = 1;
        g_seed = argc > 3 ? strtoull(argv[3], NULL, 0) : 1;
        g_mutate = !(argc > 4 && !strcmp(argv[4], "clean"));
        for (uint64_t i = 0, n = strtoull(argv[2], NULL, 0); i < n; i++) run_one(emit_sink, i);
        return 0;
    }
    uint64_t iters = argc > 1 ? strtoull(argv[1], NULL, 0) : 100000;
    g_seed = argc > 2 ? strtoull(argv[2], NULL, 0) : 1;
    uint64_t first = argc > 3 ? strtoull(argv[3], NULL, 0) : 0;

#ifdef __SANITIZE_ADDRESS__
    __sanitizer_set_death_callback(report);
#else
    const int fatal[] = { SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT };
    for (size_t i = 0; i < sizeof(fatal) / sizeof(fatal[0]); i++) signal(fatal[i], on_fatal);
#endif
    signal(SIGALRM, on_fatal);
    l7_dispatch_set_enable(1, 1, 1);
    seed_check();

    for (uint64_t i = first; i < first + iters; i++) {
        if ((i - first) % FUZZ_REASM_RESET == 0) {
            reasm_reset();
            alarm(FUZZ_WATCHDOG_SEC);
        }
        run_one(dispatch_sink, i);
    }
    tcp_reasm_close(&g_reasm);
    printf("fuzz: OK seed=%llu iters=%llu", (unsigned long long)g_seed, (unsigned long long)iters);
    for (int k = 0; k < K_KINDS; k++) printf(" %s=%ld/%ld", KIND_NAME[k], g_hits[k], g_runs[k]);
    putchar('\n');
    return 0;
}
