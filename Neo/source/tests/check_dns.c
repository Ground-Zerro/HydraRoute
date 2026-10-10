#include "pkt.h"
#include "../include/dns.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t g_target_off;

static void response(pkt_t *p, uint16_t id, uint32_t ttl, const char *cname, const uint8_t *ips, int n) {
    dns_header(p, id, (uint16_t)(n + 1));
    g_target_off = p->n + 12;
    add_cname(p, ttl, cname);
    for (int i = 0; i < n; i++) add_a(p, (uint16_t)(0xC000 | g_target_off), ttl, ips[i]);
}

static int repeat_of(const pkt_t *p, uint32_t now_ms) {
    static dns_result_t r;
    assert(dns_parse_response(p->b, (int)p->n, &r) == 0);
    assert(r.answer_count > 0 && r.cname_count == 1);
    return dns_result_repeat(&r, now_ms);
}

static void check_repeat(void) {
    pkt_t p;
    const uint8_t ab[] = { 1, 2 }, ba[] = { 2, 1 }, ac[] = { 1, 3 };

    response(&p, 0x1111, 300, "edge.example.net", ab, 2);
    assert(repeat_of(&p, 100000) == 0);
    response(&p, 0x2222, 17, "edge.example.net", ba, 2);
    assert(repeat_of(&p, 100500) == 1);
    response(&p, 0x3333, 300, "edge.example.net", ac, 2);
    assert(repeat_of(&p, 100600) == 0);
    response(&p, 0x4444, 300, "other.example.net", ab, 2);
    assert(repeat_of(&p, 100700) == 0);
    response(&p, 0x5555, 300, "edge.example.net", ab, 2);
    assert(repeat_of(&p, 101900) == 1);
    assert(repeat_of(&p, 102000) == 0);
    assert(repeat_of(&p, 103999) == 1);
    assert(repeat_of(&p, 104000) == 0);
}

static void check_long_name(void) {
    pkt_t p;
    p.n = 0;
    put16(&p, 1); put16(&p, 0x8180); put16(&p, 1); put16(&p, 1); put16(&p, 0); put16(&p, 0);
    for (int k = 0; k < 5; k++) {
        put8(&p, 63);
        memset(p.b + p.n, 'a' + k, 63);
        p.n += 63;
    }
    put8(&p, 0);
    put16(&p, 1); put16(&p, 1);
    add_a(&p, 0xC00C, 60, 9);
    static dns_result_t r;
    dns_parse_response(p.b, (int)p.n, &r);
    assert(r.answer_count == 0);
}

int main(void) {
    check_repeat();
    check_long_name();
    puts("check_dns: OK");
    return 0;
}
