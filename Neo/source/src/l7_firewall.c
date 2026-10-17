#include "../include/l7_firewall.h"
#include "../include/iptables.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int detect_wan_from_proc(char *out, size_t out_size) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;

    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }

    while (fgets(line, sizeof(line), f)) {
        char iface[64];
        char dest[16];
        if (sscanf(line, "%63s %15s", iface, dest) != 2) continue;
        if (strcmp(dest, "00000000") == 0) {
            strncpy(out, iface, out_size - 1);
            out[out_size - 1] = '\0';
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static int iface_exists(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s", name);
    struct stat st;
    return stat(path, &st) == 0;
}

int l7_firewall_resolve_wan(const config_t *cfg, char *out, size_t out_size) {
    if (cfg->l7_wan_interface[0] != '\0') {
        if (iface_exists(cfg->l7_wan_interface)) {
            strncpy(out, cfg->l7_wan_interface, out_size - 1);
            out[out_size - 1] = '\0';
            return 0;
        }
        LOG_WARN("L7 WAN '%s' from config does not exist; falling back to auto-detect",
                 cfg->l7_wan_interface);
    }
    return detect_wan_from_proc(out, out_size);
}

int l7_firewall_load_modules(void) {
    static const char *const modules[] = {"nfnetlink_log", "xt_NFLOG", "xt_connbytes"};
    for (size_t i = 0; i < sizeof(modules) / sizeof(modules[0]); i++)
        if (load_kmod(modules[i]) != 0) return -1;
    return 0;
}

static const char *const L7_CMDS[]    = {"iptables", "ip6tables"};
static const char *const L7_RESTORE[] = {"iptables-restore", "ip6tables-restore"};

#define L7_CHAIN       "FORWARD"
#define L7_BATCH_SIZE  2048

#define QUIC_INITIAL_PACKETS_MAX 3
#define QUIC_CONNBYTES_TOKEN "--connbytes 0:"
#define TCP_LENGTH_TOKEN     "--length 41:"

typedef struct {
    int dport;
    int connbytes_max;
} l7_rule_spec_t;

static void l7_rule_specs(const config_t *cfg, l7_rule_spec_t specs[2]) {
    int max443 = cfg->l7_connbytes_max > 0 ? cfg->l7_connbytes_max : 8;
    specs[0].dport = 443;
    specs[0].connbytes_max = max443;
    specs[1].dport = 80;
    specs[1].connbytes_max = max443 < 4 ? max443 : 4;
}

static int dump_has_rule(const char *dump, const char *wan,
                         const char *proto, int dport, int group, const char *extra) {
    static const char c_tok[] = "-A " L7_CHAIN " ";
    char o_tok[MAX_INTERFACE_NAME + 8], p_tok[16], d_tok[24], g_tok[32];
    snprintf(o_tok, sizeof(o_tok), "-o %s ", wan);
    snprintf(p_tok, sizeof(p_tok), "-p %s ", proto);
    snprintf(d_tok, sizeof(d_tok), "--dport %d ", dport);
    snprintf(g_tok, sizeof(g_tok), "--nflog-group %d", group);

    const char *line = dump;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        if (line_find(line, len, c_tok) == line &&
            line_find(line, len, o_tok) && line_find(line, len, p_tok) &&
            line_find(line, len, d_tok) && line_find(line, len, g_tok) &&
            (!extra || line_find(line, len, extra)))
            return 1;
        line = nl ? nl + 1 : NULL;
    }
    return 0;
}

int l7_firewall_emit_rules(const config_t *cfg, const char *wan,
                           const char *dump, char *out, size_t out_size) {
    if (!wan || wan[0] == '\0') return 0;
    l7_rule_spec_t specs[2];
    l7_rule_specs(cfg, specs);
    int group = cfg->l7_nflog_group;
    size_t off = 0;

    for (int p = 0; p < 2; p++) {
        if (dump_has_rule(dump, wan, "tcp", specs[p].dport, group, TCP_LENGTH_TOKEN))
            continue;
        int n = snprintf(out + off, out_size - off,
            "-A " L7_CHAIN " -o %s -p tcp --dport %d --tcp-flags SYN,ACK ACK "
            "-m connbytes --connbytes-dir original --connbytes-mode packets "
            "--connbytes 2:%d -m length " TCP_LENGTH_TOKEN " "
            "-j NFLOG --nflog-group %d\n",
            wan, specs[p].dport, specs[p].connbytes_max, group);
        if (n < 0 || (size_t)n >= out_size - off) return -1;
        off += (size_t)n;
    }

    if (cfg->l7_enable_quic && !dump_has_rule(dump, wan, "udp", 443, group, QUIC_CONNBYTES_TOKEN)) {
        int n = snprintf(out + off, out_size - off,
            "-A " L7_CHAIN " -o %s -p udp --dport 443 "
            "-m connbytes --connbytes-dir original --connbytes-mode packets "
            QUIC_CONNBYTES_TOKEN "%d -m length --length 1200: "
            "-j NFLOG --nflog-group %d\n",
            wan, QUIC_INITIAL_PACKETS_MAX, group);
        if (n < 0 || (size_t)n >= out_size - off) return -1;
        off += (size_t)n;
    }
    return (int)off;
}

int l7_firewall_apply(const config_t *cfg, const char *wan) {
    static char dump[IPT_DUMP_SIZE];
    static char batch[L7_BATCH_SIZE];
    static const char head[] = "*mangle\n", tail[] = "COMMIT\n";

    for (int fi = 0; fi < 2; fi++) {
        char *argv[] = {(char *)L7_CMDS[fi], "-w", "-t", "mangle", "-S", L7_CHAIN, NULL};
        if (run_command_output(L7_CMDS[fi], argv, dump, sizeof(dump)) != 0) {
            LOG_WARN("%s -t mangle -S " L7_CHAIN " failed or output truncated", L7_CMDS[fi]);
            return -1;
        }
        size_t off = sizeof(head) - 1;
        memcpy(batch, head, off);
        int n = l7_firewall_emit_rules(cfg, wan, dump, batch + off,
                                       sizeof(batch) - off - (sizeof(tail) - 1));
        if (n < 0) {
            LOG_WARN("%s: L7 batch overflow (%zu bytes)", L7_RESTORE[fi], sizeof(batch));
            return -1;
        }
        if (n == 0) continue;
        off += (size_t)n;
        memcpy(batch + off, tail, sizeof(tail) - 1);
        off += sizeof(tail) - 1;
        LOG_INFO("Adding L7 NFLOG rules via %s (wan=%s)", L7_RESTORE[fi], wan);
        if (iptables_restore(L7_RESTORE[fi], batch, off) != 0) return -1;
    }
    return 0;
}

int l7_firewall_remove(const config_t *cfg, const char *wan_iface) {
    if (!wan_iface || wan_iface[0] == '\0') return -1;

    char o_tok[MAX_INTERFACE_NAME + 8], g_tok[32];
    snprintf(o_tok, sizeof(o_tok), "-o %s ", wan_iface);
    snprintf(g_tok, sizeof(g_tok), "--nflog-group %d", cfg->l7_nflog_group);

    for (int c = 0; c < 2; c++)
        iptables_delete_rules_matching(L7_CMDS[c], L7_CHAIN, o_tok, g_tok);

    return 0;
}
