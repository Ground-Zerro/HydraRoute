#include "../include/iptables.h"
#include "../include/iptables_rules.h"
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

void iptables_delete_rules_matching(const char *ipt_cmd, const char *chain,
                                    const char *needle1, const char *needle2) {
    char *argv[] = {(char *)ipt_cmd, "-w", "-t", "mangle", "-S", (char *)chain, NULL};
    char output[IPT_DUMP_SIZE];
    if (run_command_output(ipt_cmd, argv, output, sizeof(output)) != 0) return;

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
    char ipv6_net[64];
    get_br0_global_ipv6(ipv6_net, sizeof(ipv6_net));

    char policy_marks[MAX_POLICY_ORDER + MAX_INTERFACES][16];
    int incomplete = 0;

    for (int i = 0; i < count; i++) {
        policy_marks[i][0] = '\0';
        if (targets[i].is_interface) continue;

        int r = rci_get_policy_mark(targets[i].pair.ipv4, policy_marks[i],
                                    sizeof(policy_marks[i]));
        if (r < 0) {
            LOG_WARN("RCI unreachable while reading policy %s", targets[i].pair.ipv4);
            return -1;
        }
        if (r == 0) {
            LOG_WARN("Policy %s has no mark ID yet", targets[i].pair.ipv4);
            incomplete = 1;
        }
    }

    static connmark_family_t fams[2] = {
        { .ipt_cmd = "iptables",  .restore_cmd = "iptables-restore"  },
        { .ipt_cmd = "ip6tables", .restore_cmd = "ip6tables-restore" },
    };

    for (int fi = 0; fi < 2; fi++) {
        connmark_family_t *fam = &fams[fi];
        char *argv[] = {(char *)fam->ipt_cmd, "-w", "-t", "mangle", "-S", NULL};
        if (run_command_output(fam->ipt_cmd, argv, fam->dump, sizeof(fam->dump)) != 0) {
            LOG_WARN("%s -t mangle -S failed or output truncated", fam->ipt_cmd);
            return -1;
        }
        fam->off = 0;
        fam->rule_count = 0;
        if (batch_append(fam, "*mangle\n") != 0) return -1;
    }

    const char *pkt_cond = cfg->global_routing ? "" : "-m mark ! --mark 0xffffaa0/0xffffff0 ";

    for (int i = 0; i < count; i++) {
        char mark_hex[16] = {0};

        if (targets[i].is_interface) {
            snprintf(mark_hex, sizeof(mark_hex), "%x", targets[i].fwmark);
        } else {
            if (policy_marks[i][0] == '\0') continue;
            strncpy(mark_hex, policy_marks[i], sizeof(mark_hex) - 1);
        }

        for (int fi = 0; fi < 2; fi++) {
            connmark_family_t *fam = &fams[fi];
            const char *set_name = (fi == 0) ? targets[i].pair.ipv4 : targets[i].pair.ipv6;

            connmark_rule_state_t state;
            if (connmark_rule_state(fam->dump, set_name, mark_hex, &state) != 0)
                return -1;
            if (state.exact_set_rule && !state.conflicting_set_rule) continue;
            if (fi == 1 && !targets[i].is_interface && ipv6_net[0] == '\0') continue;

            if (state.conflicting_set_rule) {
                char needle[128];
                snprintf(needle, sizeof(needle), "--match-set %s ", set_name);
                LOG_INFO("Mark changed for %s -> %s, recreating", set_name, mark_hex);
                iptables_delete_rules_matching(fam->ipt_cmd, "PREROUTING", needle, NULL);
            }

            char rule[512];
            if (connmark_format_set_rule(rule, sizeof(rule), pkt_cond,
                                          set_name, mark_hex) != 0 ||
                batch_append(fam, "%s", rule) != 0)
                return -1;
            if (connmark_format_restore_rule(rule, sizeof(rule), set_name) != 0 ||
                batch_append(fam, "%s", rule) != 0)
                return -1;
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

    return incomplete ? -1 : 0;
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
