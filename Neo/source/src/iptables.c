#include "../include/iptables.h"
#include "../include/l7_firewall.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char mark[16];
    int  xmark, restore;
} rule_state_t;

typedef struct {
    rule_state_t fam[2];
    char mark[16];
    int  gone;
} target_state_t;

static const char *next_set_rule(const char **cursor, const char *pattern, size_t *len) {
    while (*cursor && **cursor) {
        const char *line = *cursor;
        const char *nl = strchr(line, '\n');
        *len = nl ? (size_t)(nl - line) : strlen(line);
        *cursor = nl ? nl + 1 : NULL;
        if (line_find(line, *len, "-A PREROUTING ") == line && line_find(line, *len, pattern))
            return line;
    }
    return NULL;
}

static void scan_rules(const char *dump, const char *set_name, rule_state_t *st) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "--match-set %s dst ", set_name);
    st->xmark = st->restore = 0;

    size_t len;
    const char *cur = dump, *line;
    while ((line = next_set_rule(&cur, pattern, &len))) {
        if (line_find(line, len, "--restore-mark")) {
            st->restore = 1;
            continue;
        }
        const char *xmark = line_find(line, len, "--set-xmark ");
        if (st->xmark || !xmark) continue;
        xmark += 12;
        if (xmark[0] == '0' && (xmark[1] == 'x' || xmark[1] == 'X'))
            xmark += 2;
        const char *slash = line_find(xmark, len - (size_t)(xmark - line), "/");
        size_t mlen = slash ? (size_t)(slash - xmark) : 0;
        if (mlen > 0 && mlen < sizeof(st->mark)) {
            memcpy(st->mark, xmark, mlen);
            st->mark[mlen] = '\0';
            st->xmark = 1;
        }
    }
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
    int  rebuild;
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

static int batch_delete_rules(connmark_family_t *fam, const char *set_name) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "--match-set %s dst ", set_name);

    int found = 0;
    size_t len;
    const char *cur = fam->dump, *line;
    while ((line = next_set_rule(&cur, pattern, &len))) {
        if (batch_append(fam, "-D%.*s\n", (int)len - 2, line + 2) != 0) return -1;
        found = 1;
    }
    fam->rule_count += found;
    return 0;
}

static inline const char *family_set(const unified_target_t *t, int fi) {
    return fi ? t->pair.ipv6 : t->pair.ipv4;
}

static int resolve_mark(const unified_target_t *t, int need_rci, target_state_t *ts) {
    if (t->is_interface) {
        snprintf(ts->mark, sizeof(ts->mark), "%x", t->fwmark);
        return 0;
    }
    if (!need_rci) return 0;
    int r = rci_get_policy_mark(t->pair.ipv4, ts->mark, sizeof(ts->mark));
    if (r == RCI_MARK_OK) return 0;
    if (r == RCI_MARK_TRANSPORT) {
        LOG_WARN("RCI unreachable while reading policy %s", t->pair.ipv4);
    } else if (r == RCI_MARK_DENIED) {
        LOG_WARN("RCI denied reading policy %s: access token required or rejected",
                 t->pair.ipv4);
    } else {
        LOG_WARN("Policy %s has no mark ID yet", t->pair.ipv4);
        ts->gone = 1;
    }
    return -1;
}

int apply_unified_connmark_rules(const unified_target_t *targets, int count,
                                 const config_t *cfg, const char *l7_wan) {
    static int startup_audit = 1;
    static connmark_family_t fams[2];
    static target_state_t states[MAX_TARGETS];

    int incomplete = 0;

    fams[0].ipt_cmd = "iptables";  fams[0].restore_cmd = "iptables-restore";
    fams[1].ipt_cmd = "ip6tables"; fams[1].restore_cmd = "ip6tables-restore";

    int chain_count = (l7_wan && l7_wan[0]) ? 3 : 1;

    for (int fi = 0; fi < 2; fi++) {
        connmark_family_t *fam = &fams[fi];
        if (dump_chains(fam, chain_count) != 0) return -1;
        fam->off = 0;
        fam->rule_count = 0;
        fam->rebuild = startup_audit;
        if (batch_append(fam, "*mangle\n") != 0) return -1;
    }

    for (int i = 0; i < count; i++) {
        const unified_target_t *t = &targets[i];
        target_state_t *ts = &states[i];
        int need_rci = startup_audit, broken[2] = {0, 0};
        ts->mark[0] = '\0';
        ts->gone = 0;

        for (int fi = 0; fi < 2; fi++) {
            rule_state_t *st = &ts->fam[fi];
            scan_rules(fams[fi].dump, family_set(t, fi), st);
            broken[fi] = !st->xmark || !st->restore;
            if (!st->xmark) need_rci = 1;
        }
        if (!startup_audit && !broken[0] && !broken[1]) continue;
        if (resolve_mark(t, need_rci, ts) != 0) incomplete = 1;

        for (int fi = 0; fi < 2; fi++) {
            if (!broken[fi] || fams[fi].rebuild) continue;
            if (!ts->mark[0] && !ts->fam[fi].xmark) continue;
            LOG_INFO("%s: rules for %s are missing, rebuilding all CONNMARK rules in PolicyOrder",
                     fams[fi].ipt_cmd, family_set(t, fi));
            fams[fi].rebuild = 1;
        }
    }

    for (int fi = 0; fi < 2; fi++) {
        if (!fams[fi].rebuild) continue;
        for (int i = 0; i < count; i++)
            if (batch_delete_rules(&fams[fi], family_set(&targets[i], fi)) != 0) return -1;
    }

    const char *pkt_cond = cfg->global_routing ? "" : "-m mark ! --mark 0xffffaa0/0xffffff0 ";

    for (int i = 0; i < count; i++) {
        const unified_target_t *t = &targets[i];
        const target_state_t *ts = &states[i];

        for (int fi = 0; fi < 2; fi++) {
            connmark_family_t *fam = &fams[fi];
            const rule_state_t *st = &ts->fam[fi];
            const char *set_name = family_set(t, fi);

            if (ts->gone) {
                if (!st->xmark && !st->restore) continue;
                LOG_INFO("Policy %s is gone, removing orphaned rules for %s",
                         t->pair.ipv4, set_name);
                if (!fam->rebuild && batch_delete_rules(fam, set_name) != 0) return -1;
                continue;
            }
            if (!fam->rebuild) continue;
            const char *mark = ts->mark[0] ? ts->mark : st->xmark ? st->mark : NULL;
            if (!mark) continue;
            if (st->xmark && strcmp(st->mark, mark) != 0)
                LOG_INFO("Mark changed for %s: %s -> %s", set_name, st->mark, mark);

            if (batch_append(fam,
                    "-A PREROUTING %s-m connmark --mark 0x0/0xffffffff -m set --match-set %s dst -j CONNMARK --set-xmark 0x%s/0xffffffff\n",
                    pkt_cond, set_name, mark) != 0) return -1;
            if (batch_append(fam,
                    "-A PREROUTING -m set --match-set %s dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n",
                    set_name) != 0) return -1;
            fam->rule_count++;
            LOG_INFO("Adding rules for %s (mark: 0x%s) via %s",
                     set_name, mark, fam->restore_cmd);
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
