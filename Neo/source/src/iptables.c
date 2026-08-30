#include "../include/iptables.h"
#include "../include/l7_firewall.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void get_br0_global_ipv6(char *ipv6_net, int ipv6_size) {
    ipv6_net[0] = '\0';

    char *argv[] = {"ip", "addr", "show", "br0", NULL};
    char output[4096];
    if (run_command_output("ip", argv, output, sizeof(output)) != 0) {
        LOG_ERROR("ip addr show br0 failed");
        return;
    }

    char *saveptr;
    char *line = strtok_r(output, "\n", &saveptr);
    while (line) {
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "inet6 ", 6) == 0 && strstr(line, "scope global")) {
            char *addr = line + 6;
            char *sp = strchr(addr, ' ');
            if (sp) *sp = '\0';
            strncpy(ipv6_net, addr, ipv6_size - 1);
            ipv6_net[ipv6_size - 1] = '\0';
            return;
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
}

static int find_mark_in_rules(const char *dump, const char *ipset_name,
                              char *mark_out, size_t mark_size) {
    char match_pattern[128];
    snprintf(match_pattern, sizeof(match_pattern), "--match-set %s dst", ipset_name);

    const char *line = dump;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);

        if (line_find(line, len, "-A PREROUTING ") == line &&
            line_find(line, len, match_pattern)) {
            const char *xmark = line_find(line, len, "--set-xmark ");
            if (xmark) {
                xmark += 12;
                if (xmark[0] == '0' && (xmark[1] == 'x' || xmark[1] == 'X'))
                    xmark += 2;
                const char *slash = line_find(xmark, len - (size_t)(xmark - line), "/");
                size_t mlen = slash ? (size_t)(slash - xmark) : 0;
                if (mlen > 0 && mlen < mark_size) {
                    memcpy(mark_out, xmark, mlen);
                    mark_out[mlen] = '\0';
                    return 1;
                }
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return 0;
}

void iptables_delete_rules_matching(const char *ipt_cmd, const char *chain,
                                    const char *needle1, const char *needle2) {
    char *argv[] = {(char *)ipt_cmd, "-w", "-t", "mangle", "-S", (char *)chain, NULL};
    char output[IPT_DUMP_SIZE];
    if (run_command_output(ipt_cmd, argv, output, sizeof(output)) != 0) {
        LOG_WARN("%s -t mangle -S %s failed or output truncated", ipt_cmd, chain);
        return;
    }

    char *line = output;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strncmp(line, "-A ", 3) == 0 && strstr(line, needle1) &&
            (!needle2 || strstr(line, needle2))) {
            const char *src = line + 3;
            size_t chain_len = strlen(chain);
            if (strncmp(src, chain, chain_len) == 0 && src[chain_len] == ' ')
                src += chain_len + 1;

            char *del_argv[IPT_MAX_RULE_ARGS];
            del_argv[0] = (char *)ipt_cmd;
            del_argv[1] = "-w";
            del_argv[2] = "-t";
            del_argv[3] = "mangle";
            del_argv[4] = "-D";
            del_argv[5] = (char *)chain;

            char args_buf[512];
            if (strlen(src) >= sizeof(args_buf)) {
                LOG_ERROR("Rule too long to delete in %s %s: %s", ipt_cmd, chain, src);
                line = nl ? nl + 1 : NULL;
                continue;
            }
            strcpy(args_buf, src);
            int argc = 6;
            char *saveptr_rule;
            char *tok = strtok_r(args_buf, " \t", &saveptr_rule);
            while (tok && argc < IPT_MAX_RULE_ARGS - 1) {
                del_argv[argc++] = tok;
                tok = strtok_r(NULL, " \t", &saveptr_rule);
            }
            if (tok) {
                LOG_ERROR("Rule has too many arguments to delete in %s %s", ipt_cmd, chain);
                line = nl ? nl + 1 : NULL;
                continue;
            }
            del_argv[argc] = NULL;

            char discard[256];
            if (run_command_output(ipt_cmd, del_argv, discard, sizeof(discard)) != 0)
                LOG_WARN("%s -t mangle -D %s failed: %s", ipt_cmd, chain, discard);
        }

        line = nl ? nl + 1 : NULL;
    }
}

typedef struct {
    const char *ipt_cmd;
    const char *restore_cmd;
    char dump[IPT_DUMP_SIZE];
    char batch[IPT_BATCH_SIZE];
    int  off;
    int  rule_count;
} connmark_family_t;

static const char *const DUMP_CHAINS[] = {"PREROUTING", "FORWARD", "OUTPUT"};

static int dump_chains(connmark_family_t *fam, int chain_count) {
    size_t off = 0;
    for (int c = 0; c < chain_count; c++) {
        char *argv[] = {(char *)fam->ipt_cmd, "-w", "-t", "mangle", "-S",
                        (char *)DUMP_CHAINS[c], NULL};
        if (run_command_output(fam->ipt_cmd, argv, fam->dump + off,
                               sizeof(fam->dump) - off) != 0) {
            LOG_WARN("%s -t mangle -S %s failed or output truncated",
                     fam->ipt_cmd, DUMP_CHAINS[c]);
            return -1;
        }
        off += strlen(fam->dump + off);
    }
    return 0;
}

static int batch_append(connmark_family_t *fam, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(fam->batch + fam->off, sizeof(fam->batch) - fam->off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof(fam->batch) - fam->off) {
        LOG_ERROR("%s batch overflow (%zu bytes)", fam->restore_cmd, sizeof(fam->batch));
        return -1;
    }
    fam->off += n;
    return 0;
}

int apply_unified_connmark_rules(const unified_target_t *targets, int count,
                                 const config_t *cfg, const char *l7_wan) {
    static int startup_audit = 1;

    char ipv6_net[64];
    get_br0_global_ipv6(ipv6_net, sizeof(ipv6_net));

    int incomplete = 0;

    static connmark_family_t fams[2];
    fams[0].ipt_cmd = "iptables";  fams[0].restore_cmd = "iptables-restore";
    fams[1].ipt_cmd = "ip6tables"; fams[1].restore_cmd = "ip6tables-restore";

    int chain_count = (l7_wan && l7_wan[0]) ? 3 : 1;

    for (int fi = 0; fi < 2; fi++) {
        connmark_family_t *fam = &fams[fi];
        if (dump_chains(fam, chain_count) != 0) return -1;
        fam->off = 0;
        fam->rule_count = 0;
        if (batch_append(fam, "*mangle\n") != 0) return -1;
    }

    const char *pkt_cond = cfg->global_routing ? "" : "-m mark ! --mark 0xffffaa0/0xffffff0 ";

    for (int i = 0; i < count; i++) {
        const char *set_names[2] = { targets[i].pair.ipv4, targets[i].pair.ipv6 };
        char present_mark[2][16];
        int  present[2] = {0, 0}, skip[2] = {0, 0};
        int  need_mark = startup_audit;

        for (int fi = 0; fi < 2; fi++) {
            if (fi == 1 && !targets[i].is_interface && ipv6_net[0] == '\0') {
                skip[fi] = 1;
                continue;
            }
            present[fi] = find_mark_in_rules(fams[fi].dump, set_names[fi],
                                             present_mark[fi], sizeof(present_mark[fi]));
            if (!present[fi]) need_mark = 1;
        }
        if (!need_mark) continue;

        char mark_hex[16] = {0};
        if (targets[i].is_interface) {
            snprintf(mark_hex, sizeof(mark_hex), "%x", targets[i].fwmark);
        } else {
            int r = rci_get_policy_mark(set_names[0], mark_hex, sizeof(mark_hex));
            if (r == RCI_MARK_TRANSPORT) {
                LOG_WARN("RCI unreachable while reading policy %s", set_names[0]);
                incomplete = 1;
                continue;
            }
            if (r == RCI_MARK_DENIED) {
                LOG_WARN("RCI denied reading policy %s: access token required or rejected",
                         set_names[0]);
                incomplete = 1;
                continue;
            }
            if (r == RCI_MARK_ABSENT) {
                LOG_WARN("Policy %s has no mark ID yet", set_names[0]);
                incomplete = 1;
                for (int fi = 0; fi < 2; fi++) {
                    if (skip[fi] || !present[fi]) continue;
                    char needle[128];
                    snprintf(needle, sizeof(needle), "--match-set %s ", set_names[fi]);
                    LOG_INFO("Policy %s is gone, removing orphaned rules for %s",
                             set_names[0], set_names[fi]);
                    iptables_delete_rules_matching(fams[fi].ipt_cmd, "PREROUTING",
                                                   needle, NULL);
                }
                continue;
            }
        }

        for (int fi = 0; fi < 2; fi++) {
            connmark_family_t *fam = &fams[fi];
            const char *set_name = set_names[fi];

            if (skip[fi]) continue;
            if (present[fi]) {
                if (!startup_audit) continue;
                if (strcmp(present_mark[fi], mark_hex) == 0) continue;
                char needle[128];
                snprintf(needle, sizeof(needle), "--match-set %s ", set_name);
                LOG_INFO("Mark changed for %s: %s -> %s, recreating",
                         set_name, present_mark[fi], mark_hex);
                iptables_delete_rules_matching(fam->ipt_cmd, "PREROUTING", needle, NULL);
            }

            if (batch_append(fam,
                    "-A PREROUTING %s-m connmark --mark 0x0/0xffffffff -m set --match-set %s dst -j CONNMARK --set-xmark 0x%s/0xffffffff\n",
                    pkt_cond, set_name, mark_hex) != 0) return -1;
            if (batch_append(fam,
                    "-A PREROUTING -m set --match-set %s dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n",
                    set_name) != 0) return -1;
            fam->rule_count++;
            LOG_INFO("Adding rules for %s (mark: 0x%s) via %s",
                     set_name, mark_hex, fam->restore_cmd);
        }
    }

    if (l7_wan && l7_wan[0]) {
        for (int fi = 0; fi < 2; fi++) {
            connmark_family_t *fam = &fams[fi];
            int n = l7_firewall_emit_rules(cfg, l7_wan, fam->dump,
                                           fam->batch + fam->off,
                                           sizeof(fam->batch) - fam->off);
            if (n < 0) {
                LOG_ERROR("%s batch overflow while emitting L7 rules", fam->restore_cmd);
                return -1;
            }
            if (n > 0) {
                fam->off += n;
                fam->rule_count++;
                LOG_INFO("Adding L7 NFLOG rules via %s (wan=%s)", fam->restore_cmd, l7_wan);
            }
        }
    }

    for (int fi = 0; fi < 2; fi++) {
        connmark_family_t *fam = &fams[fi];
        if (fam->rule_count == 0) continue;
        if (batch_append(fam, "COMMIT\n") != 0) return -1;
        char *argv[] = {(char *)fam->restore_cmd, "--noflush", NULL};
        int ret = run_command_stdin(fam->restore_cmd, argv, fam->batch, fam->off);
        if (ret != 0) {
            LOG_WARN("%s failed (exit %d)", fam->restore_cmd, ret);
            return -1;
        }
        LOG_DEBUG("Committed %d rule groups via %s", fam->rule_count, fam->restore_cmd);
    }

    if (incomplete) return -1;
    startup_audit = 0;
    return 0;
}

int cleanup_connmark_rules(const ipset_pair_t *pairs, int count) {
    for (int i = 0; i < count; i++) {
        char needle[128];
        snprintf(needle, sizeof(needle), "--match-set %s ", pairs[i].ipv4);
        iptables_delete_rules_matching("iptables", "PREROUTING", needle, NULL);
        snprintf(needle, sizeof(needle), "--match-set %s ", pairs[i].ipv6);
        iptables_delete_rules_matching("ip6tables", "PREROUTING", needle, NULL);
    }
    LOG_INFO("CONNMARK rules cleaned up");
    return 0;
}
