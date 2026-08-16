#include "../include/iptables.h"
#include "../include/l7_firewall.h"
#include "../include/util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

void iptables_delete_rules_matching(const char *c, const char *ch,
                                    const char *n1, const char *n2) {
    (void)c; (void)ch; (void)n1; (void)n2;
}

static void check_line_find(void) {
    const char *dump =
        "-A PREROUTING -m set --match-set hr_youtube dst -j CONNMARK --set-xmark 0xf00/0xffffffff\n"
        "-A PREROUTING -m set --match-set hr_youtube_extra dst -j ACCEPT\n";
    const char *first_nl = strchr(dump, '\n');
    size_t len = (size_t)(first_nl - dump);

    assert(line_find(dump, len, "-A PREROUTING ") == dump);
    assert(line_find(dump, len, "--match-set hr_youtube dst") != NULL);
    assert(line_find(dump, len, "--set-xmark ") != NULL);
    assert(line_find(dump, len, "--match-set hr_youtube_extra") == NULL);
    assert(line_find(dump, len, "-j ACCEPT") == NULL);
}

static config_t make_cfg(void) {
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.l7_nflog_group = 210;
    cfg.l7_connbytes_max = 8;
    cfg.l7_enable_quic = 1;
    return cfg;
}

static void check_emit_from_empty(void) {
    config_t cfg = make_cfg();
    char out[4096];
    int n = l7_firewall_emit_rules(&cfg, "eth3", "", out, sizeof(out));
    assert(n > 0);
    out[n] = '\0';

    int lines = 0;
    for (int i = 0; i < n; i++) if (out[i] == '\n') lines++;
    assert(lines == 6);

    assert(strstr(out, "-A FORWARD -o eth3 -p tcp --dport 443 "));
    assert(strstr(out, "-A FORWARD -o eth3 -p tcp --dport 80 "));
    assert(strstr(out, "-A OUTPUT -o eth3 -p udp --dport 443 "));
    assert(strstr(out, "--connbytes 2:8 "));
    assert(strstr(out, "--connbytes 2:4 "));
    assert(strstr(out, "--nflog-group 210\n"));
}

static void check_emit_idempotent(void) {
    config_t cfg = make_cfg();
    char first[4096];
    int n = l7_firewall_emit_rules(&cfg, "eth3", "", first, sizeof(first));
    assert(n > 0);
    first[n] = '\0';

    char out[4096];
    assert(l7_firewall_emit_rules(&cfg, "eth3", first, out, sizeof(out)) == 0);
}

static void check_emit_partial(void) {
    config_t cfg = make_cfg();
    const char *dump =
        "-P FORWARD ACCEPT\n"
        "-A FORWARD -o eth3 -p tcp --dport 443 --tcp-flags SYN,ACK ACK "
        "-m connbytes --connbytes 2:8 --connbytes-mode packets --connbytes-dir original "
        "-m length --length 60: -j NFLOG --nflog-group 210\n";
    char out[4096];
    int n = l7_firewall_emit_rules(&cfg, "eth3", dump, out, sizeof(out));
    assert(n > 0);
    out[n] = '\0';

    int lines = 0;
    for (int i = 0; i < n; i++) if (out[i] == '\n') lines++;
    assert(lines == 5);
    assert(!strstr(out, "-A FORWARD -o eth3 -p tcp --dport 443 "));
    assert(strstr(out, "-A OUTPUT -o eth3 -p tcp --dport 443 "));
}

static void check_emit_wan_specific(void) {
    config_t cfg = make_cfg();
    char eth3[4096];
    int n = l7_firewall_emit_rules(&cfg, "eth3", "", eth3, sizeof(eth3));
    eth3[n] = '\0';

    char out[4096];
    int m = l7_firewall_emit_rules(&cfg, "ppp0", eth3, out, sizeof(out));
    assert(m == n);
}

static void check_emit_overflow(void) {
    config_t cfg = make_cfg();
    char tiny[64];
    assert(l7_firewall_emit_rules(&cfg, "eth3", "", tiny, sizeof(tiny)) == -1);
}

static void check_emit_no_wan(void) {
    config_t cfg = make_cfg();
    char out[4096];
    assert(l7_firewall_emit_rules(&cfg, "", "", out, sizeof(out)) == 0);
    assert(l7_firewall_emit_rules(&cfg, NULL, "", out, sizeof(out)) == 0);
}

static void check_emit_no_quic(void) {
    config_t cfg = make_cfg();
    cfg.l7_enable_quic = 0;
    char out[4096];
    int n = l7_firewall_emit_rules(&cfg, "eth3", "", out, sizeof(out));
    out[n] = '\0';
    int lines = 0;
    for (int i = 0; i < n; i++) if (out[i] == '\n') lines++;
    assert(lines == 4);
    assert(!strstr(out, "-p udp"));
}

static int count_tokens(const char *s) {
    int n = 0;
    while (*s) {
        while (*s == ' ') s++;
        if (!*s) break;
        n++;
        while (*s && *s != ' ') s++;
    }
    return n;
}

static void check_delete_argv_capacity(void) {
    const char *canonical =
        "-o eth3 -p tcp -m tcp --dport 443 --tcp-flags SYN,ACK ACK "
        "-m connbytes --connbytes 2:8 --connbytes-mode packets --connbytes-dir original "
        "-m length --length 60:65535 -j NFLOG --nflog-group 210";
    assert(strlen(canonical) < 512);
    assert(6 + count_tokens(canonical) + 1 <= IPT_MAX_RULE_ARGS);
}

int main(void) {
    check_line_find();
    check_delete_argv_capacity();
    check_emit_from_empty();
    check_emit_idempotent();
    check_emit_partial();
    check_emit_wan_specific();
    check_emit_overflow();
    check_emit_no_wan();
    check_emit_no_quic();
    printf("check_nf: all assertions passed\n");
    return 0;
}
