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

static const char *g_dump[2];
static char g_batch[2][4096];
static int g_restores, g_restore_rc;

static int family_of(const char *cmd) {
    return strncmp(cmd, "ip6", 3) == 0;
}

int __wrap_run_command_output(const char *cmd, char *const argv[], char *output, size_t size) {
    assert(strcmp(argv[4], "-S") == 0 && strcmp(argv[5], "FORWARD") == 0);
    snprintf(output, size, "%s", g_dump[family_of(cmd)]);
    return 0;
}

int iptables_restore(const char *restore_cmd, const char *batch, size_t len) {
    int fi = family_of(restore_cmd);
    assert(len < sizeof(g_batch[fi]));
    memcpy(g_batch[fi], batch, len);
    g_batch[fi][len] = '\0';
    g_restores++;
    return g_restore_rc;
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
    assert(lines == 3);

    assert(strstr(out, "-A FORWARD -o eth3 -p tcp --dport 443 "));
    assert(strstr(out, "-A FORWARD -o eth3 -p tcp --dport 80 "));
    assert(!strstr(out, "OUTPUT"));
    assert(strstr(out, "--connbytes 2:8 "));
    assert(strstr(out, "--connbytes 2:4 "));
    assert(strstr(out, "--nflog-group 210\n"));
    assert(strstr(out, "-A FORWARD -o eth3 -p udp --dport 443 -m connbytes --connbytes-dir original "
                       "--connbytes-mode packets --connbytes 0:3 -m length --length 1200: "));
}

static void check_emit_quic_window(void) {
    config_t cfg = make_cfg();
    const char *unbounded =
        "-A FORWARD -o eth3 -p udp -m udp --dport 443 -m length --length 1200:65535 -j NFLOG --nflog-group 210\n";
    char out[4096];
    int n = l7_firewall_emit_rules(&cfg, "eth3", unbounded, out, sizeof(out));
    assert(n > 0);
    out[n] = '\0';
    assert(strstr(out, "-A FORWARD -o eth3 -p udp --dport 443 "));
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
        "-m length --length 41: -j NFLOG --nflog-group 210\n";
    char out[4096];
    int n = l7_firewall_emit_rules(&cfg, "eth3", dump, out, sizeof(out));
    assert(n > 0);
    out[n] = '\0';

    int lines = 0;
    for (int i = 0; i < n; i++) if (out[i] == '\n') lines++;
    assert(lines == 2);
    assert(!strstr(out, "-A FORWARD -o eth3 -p tcp --dport 443 "));
    assert(strstr(out, "-A FORWARD -o eth3 -p tcp --dport 80 "));
    assert(strstr(out, "-A FORWARD -o eth3 -p udp --dport 443 "));
}

static void check_emit_old_length(void) {
    config_t cfg = make_cfg();
    const char *dump =
        "-A FORWARD -o eth3 -p tcp -m tcp --dport 443 --tcp-flags SYN,ACK ACK "
        "-m connbytes --connbytes 2:8 --connbytes-mode packets --connbytes-dir original "
        "-m length --length 60:65535 -j NFLOG --nflog-group 210\n";
    char out[4096];
    int n = l7_firewall_emit_rules(&cfg, "eth3", dump, out, sizeof(out));
    assert(n > 0);
    out[n] = '\0';
    assert(strstr(out, "-A FORWARD -o eth3 -p tcp --dport 443 "));
    assert(strstr(out, "-m length --length 41: -j NFLOG"));
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
    assert(lines == 2);
    assert(!strstr(out, "-p udp"));
}

static const char CANONICAL_FORWARD[] =
        "-P FORWARD ACCEPT\n"
        "-A FORWARD -j NDMMARK --set-xndmmark 0x4/0x0\n"
        "-A FORWARD -o eth3 -p tcp -m tcp --dport 443 --tcp-flags SYN,ACK ACK "
        "-m connbytes --connbytes 2:8 --connbytes-mode packets --connbytes-dir original "
        "-m length --length 41:65535 -j NFLOG --nflog-group 210\n"
        "-A FORWARD -o eth3 -p tcp -m tcp --dport 80 --tcp-flags SYN,ACK ACK "
        "-m connbytes --connbytes 2:4 --connbytes-mode packets --connbytes-dir original "
        "-m length --length 41:65535 -j NFLOG --nflog-group 210\n"
        "-A FORWARD -o eth3 -p udp -m udp --dport 443 -m connbytes --connbytes 0:3 "
        "--connbytes-mode packets --connbytes-dir original -m length --length 1200:65535 "
        "-j NFLOG --nflog-group 210\n";

static void check_emit_canonical_dump(void) {
    config_t cfg = make_cfg();
    char out[4096];
    assert(l7_firewall_emit_rules(&cfg, "eth3", CANONICAL_FORWARD, out, sizeof(out)) == 0);
}

static void check_apply(void) {
    config_t cfg = make_cfg();
    g_dump[0] = "-P FORWARD ACCEPT\n";
    g_dump[1] = CANONICAL_FORWARD;
    g_restores = 0;
    g_restore_rc = 0;
    assert(l7_firewall_apply(&cfg, "eth3") == 0);
    assert(g_restores == 1);
    static const char head[] = "*mangle\n-A FORWARD -o eth3 -p tcp --dport 443 ";
    assert(strncmp(g_batch[0], head, sizeof(head) - 1) == 0);
    size_t len = strlen(g_batch[0]);
    assert(len > 7 && strcmp(g_batch[0] + len - 7, "COMMIT\n") == 0);
    assert(!strstr(g_batch[0], "OUTPUT"));

    g_dump[1] = "-P FORWARD ACCEPT\n";
    g_restores = 0;
    g_restore_rc = -1;
    assert(l7_firewall_apply(&cfg, "eth3") == -1);
    assert(g_restores == 1);
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
    check_emit_old_length();
    check_emit_wan_specific();
    check_emit_overflow();
    check_emit_no_wan();
    check_emit_no_quic();
    check_emit_quic_window();
    check_emit_canonical_dump();
    check_apply();
    printf("check_nf: all assertions passed\n");
    return 0;
}
