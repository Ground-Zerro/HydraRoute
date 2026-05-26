#include "../include/iptables.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int get_br0_networks(char *ipv4_net, int ipv4_size, char *ipv6_net, int ipv6_size) {
    ipv4_net[0] = '\0';
    ipv6_net[0] = '\0';

    char *argv[] = {"ip", "addr", "show", "br0", NULL};
    char output[4096];
    int ret = run_command_output("ip", argv, output, sizeof(output));
    if (ret != 0) {
        LOG_ERROR("ip addr show br0 failed");
        return -1;
    }

    char *saveptr;
    char *line = strtok_r(output, "\n", &saveptr);
    while (line) {
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "inet ", 5) == 0 && ipv4_net[0] == '\0') {
            char *addr = line + 5;
            char *sp = strchr(addr, ' ');
            if (sp) *sp = '\0';
            strncpy(ipv4_net, addr, ipv4_size - 1);
            ipv4_net[ipv4_size - 1] = '\0';
        } else if (strncmp(line, "inet6 ", 6) == 0 && strstr(line, "scope global") && ipv6_net[0] == '\0') {
            char *addr = line + 6;
            char *sp = strchr(addr, ' ');
            if (sp) *sp = '\0';
            strncpy(ipv6_net, addr, ipv6_size - 1);
            ipv6_net[ipv6_size - 1] = '\0';
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }

    if (ipv4_net[0] == '\0') {
        LOG_ERROR("No IPv4 address found for br0");
        return -1;
    }

    return 0;
}

static const char *find_mark_in_rules(const char *rules_output, const char *ipset_name) {
    static char mark_buf[16];
    char match_pattern[128];
    snprintf(match_pattern, sizeof(match_pattern), "--match-set %s dst", ipset_name);

    const char *pos = rules_output;
    while (pos && *pos) {
        const char *nl = strchr(pos, '\n');
        int line_len = nl ? (int)(nl - pos) : (int)strlen(pos);

        char *found = strstr(pos, match_pattern);
        if (found && found < pos + line_len) {
            char *xmark = strstr(pos, "--set-xmark ");
            if (xmark && xmark < pos + line_len) {
                xmark += 12;
                if (xmark[0] == '0' && (xmark[1] == 'x' || xmark[1] == 'X'))
                    xmark += 2;
                const char *slash = strchr(xmark, '/');
                int mlen = slash ? (int)(slash - xmark) : 0;
                if (mlen > 0 && mlen < 16) {
                    memcpy(mark_buf, xmark, mlen);
                    mark_buf[mlen] = '\0';
                    return mark_buf;
                }
            }
        }
        pos = nl ? nl + 1 : NULL;
    }
    return NULL;
}

static void remove_connmark_rules_for(const char *ipt_cmd, const char *ipset_name) {
    char *argv[] = {(char *)ipt_cmd, "-w", "-t", "mangle", "-S", "PREROUTING", NULL};
    char output[16384];
    int ret = run_command_output(ipt_cmd, argv, output, sizeof(output));
    if (ret != 0) return;

    char match_pattern[128];
    snprintf(match_pattern, sizeof(match_pattern), "--match-set %s ", ipset_name);

    char *line = output;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strstr(line, match_pattern)) {
            const char *src = line;
            if (strncmp(src, "-A ", 3) == 0) src += 3;
            if (strncmp(src, "PREROUTING ", 11) == 0) src += 11;

            char *del_argv[] = {(char *)ipt_cmd, "-w", "-t", "mangle", "-D", "PREROUTING", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
            char args_buf[512];
            strncpy(args_buf, src, sizeof(args_buf) - 1);
            args_buf[sizeof(args_buf) - 1] = '\0';
            int argc = 6;
            char *saveptr_rule;
            char *tok = strtok_r(args_buf, " \t", &saveptr_rule);
            while (tok && argc < 25) {
                del_argv[argc++] = tok;
                tok = strtok_r(NULL, " \t", &saveptr_rule);
            }
            char discard[64];
            run_command_output(ipt_cmd, del_argv, discard, sizeof(discard));
        }

        line = nl ? nl + 1 : NULL;
    }
}

int apply_unified_connmark_rules(rci_client_t *rci, const unified_target_t *targets,
                                 int count, int global_routing) {
    char ipv4_net[64], ipv6_net[64];
    get_br0_networks(ipv4_net, sizeof(ipv4_net), ipv6_net, sizeof(ipv6_net));

    policy_mark_t policies[MAX_POLICY_ORDER];
    int policy_count = -1;

    for (int attempt = 0; ; attempt++) {
        policy_count = rci_get_policies_with_retry(rci, policies, MAX_POLICY_ORDER);
        if (policy_count < 0) {
            LOG_ERROR("Failed to get policy data from RCI");
            return -1;
        }

        int missing = 0;
        for (int i = 0; i < count; i++) {
            if (targets[i].is_interface) continue;
            int found = 0;
            for (int p = 0; p < policy_count; p++) {
                if (strcmp(policies[p].name, targets[i].pair.ipv4) == 0 &&
                    policies[p].mark[0] != '\0') {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                LOG_WARN("Policy %s has no mark ID yet", targets[i].pair.ipv4);
                missing = 1;
            }
        }

        if (!missing || attempt >= 4) break;
        LOG_WARN("Retrying policy data fetch in 4 seconds (attempt %d/4)...", attempt + 1);
        sleep(4);
    }

    char ipv4_rules_cache[16384], ipv6_rules_cache[16384];
    {
        char *argv4[] = {"iptables", "-w", "-t", "mangle", "-S", "PREROUTING", NULL};
        run_command_output("iptables", argv4, ipv4_rules_cache, sizeof(ipv4_rules_cache));
        char *argv6[] = {"ip6tables", "-w", "-t", "mangle", "-S", "PREROUTING", NULL};
        run_command_output("ip6tables", argv6, ipv6_rules_cache, sizeof(ipv6_rules_cache));
    }

    char ipv4_batch[8192], ipv6_batch[8192];
    int ipv4_off = 0, ipv6_off = 0;
    ipv4_off += snprintf(ipv4_batch + ipv4_off, sizeof(ipv4_batch) - ipv4_off, "*mangle\n");
    ipv6_off += snprintf(ipv6_batch + ipv6_off, sizeof(ipv6_batch) - ipv6_off, "*mangle\n");
    int ipv4_rule_count = 0, ipv6_rule_count = 0;

    for (int i = 0; i < count; i++) {
        char mark_hex[16] = {0};

        if (targets[i].is_interface) {
            snprintf(mark_hex, sizeof(mark_hex), "%x", targets[i].fwmark);
        } else {
            for (int p = 0; p < policy_count; p++) {
                if (strcmp(policies[p].name, targets[i].pair.ipv4) == 0) {
                    strncpy(mark_hex, policies[p].mark, 15);
                    break;
                }
            }
            if (mark_hex[0] == '\0') {
                LOG_WARN("Policy %s has no mark ID, skipping", targets[i].pair.ipv4);
                continue;
            }
        }

        const char *current_mark = find_mark_in_rules(ipv4_rules_cache, targets[i].pair.ipv4);
        if (current_mark && strcmp(current_mark, mark_hex) == 0) {
            LOG_DEBUG("Rule for %s is current (mark: %s)", targets[i].pair.ipv4, mark_hex);
        } else {
            if (current_mark) {
                LOG_INFO("Mark changed for %s: %s -> %s, recreating",
                         targets[i].pair.ipv4, current_mark, mark_hex);
                remove_connmark_rules_for("iptables", targets[i].pair.ipv4);
            }

            const char *pkt_cond = global_routing ? "" : "-m mark ! --mark 0xffffaa0/0xffffff0 ";
            ipv4_off += snprintf(ipv4_batch + ipv4_off, sizeof(ipv4_batch) - ipv4_off,
                "-A PREROUTING %s-m connmark --mark 0x0/0xffff0000 -m set --match-set %s dst -j CONNMARK --set-xmark 0x%s/0xffffffff\n",
                pkt_cond, targets[i].pair.ipv4, mark_hex);
            ipv4_off += snprintf(ipv4_batch + ipv4_off, sizeof(ipv4_batch) - ipv4_off,
                "-A PREROUTING -m set --match-set %s dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n",
                targets[i].pair.ipv4);
            ipv4_rule_count++;
            LOG_INFO("Adding rules for %s (mark: 0x%s) via iptables-restore",
                     targets[i].pair.ipv4, mark_hex);
        }

        current_mark = find_mark_in_rules(ipv6_rules_cache, targets[i].pair.ipv6);
        if (current_mark && strcmp(current_mark, mark_hex) == 0) {
            LOG_DEBUG("Rule for %s is current (mark: %s)", targets[i].pair.ipv6, mark_hex);
        } else {
            if (targets[i].is_interface || ipv6_net[0] != '\0') {
                if (current_mark) {
                    remove_connmark_rules_for("ip6tables", targets[i].pair.ipv6);
                }

                const char *pkt_cond = global_routing ? "" : "-m mark ! --mark 0xffffaa0/0xffffff0 ";
                ipv6_off += snprintf(ipv6_batch + ipv6_off, sizeof(ipv6_batch) - ipv6_off,
                    "-A PREROUTING %s-m connmark --mark 0x0/0xffff0000 -m set --match-set %s dst -j CONNMARK --set-xmark 0x%s/0xffffffff\n",
                    pkt_cond, targets[i].pair.ipv6, mark_hex);
                ipv6_off += snprintf(ipv6_batch + ipv6_off, sizeof(ipv6_batch) - ipv6_off,
                    "-A PREROUTING -m set --match-set %s dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n",
                    targets[i].pair.ipv6);
                ipv6_rule_count++;
                LOG_INFO("Adding rules for %s (mark: 0x%s) via ip6tables-restore",
                         targets[i].pair.ipv6, mark_hex);
            }
        }
    }

    if (ipv4_rule_count > 0) {
        ipv4_off += snprintf(ipv4_batch + ipv4_off, sizeof(ipv4_batch) - ipv4_off, "COMMIT\n");
        char *argv[] = {"iptables-restore", "--noflush", NULL};
        int ret = run_command_stdin("iptables-restore", argv, ipv4_batch, ipv4_off);
        if (ret != 0) LOG_ERROR("iptables-restore failed (exit %d)", ret);
        else LOG_DEBUG("Applied %d CONNMARK rules via iptables-restore", ipv4_rule_count);
    }

    if (ipv6_rule_count > 0) {
        ipv6_off += snprintf(ipv6_batch + ipv6_off, sizeof(ipv6_batch) - ipv6_off, "COMMIT\n");
        char *argv[] = {"ip6tables-restore", "--noflush", NULL};
        int ret = run_command_stdin("ip6tables-restore", argv, ipv6_batch, ipv6_off);
        if (ret != 0) LOG_ERROR("ip6tables-restore failed (exit %d)", ret);
        else LOG_DEBUG("Applied %d CONNMARK rules via ip6tables-restore", ipv6_rule_count);
    }

    return 0;
}

int cleanup_connmark_rules(const ipset_pair_t *pairs, int count) {
    for (int i = 0; i < count; i++) {
        remove_connmark_rules_for("iptables", pairs[i].ipv4);
        remove_connmark_rules_for("ip6tables", pairs[i].ipv6);
    }
    LOG_INFO("CONNMARK rules cleaned up");
    return 0;
}
