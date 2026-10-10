#include "../include/iptables.h"
#include "../include/util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define MAX_LINES 32
#define CHAIN "HRNEO_CONNMARK"
#define OVR "HRNEO_OVERRIDE"
#define OVR_JUMP(set) "-A " CHAIN " -m mark --mark 0xffffa00/0xfffff00 -m set --match-set " set " dst -j " OVR
#define JUMP "-A PREROUTING -m addrtype ! --dst-type LOCAL -j " CHAIN
#define RESTORE(m) "-A " CHAIN " -m connmark --mark 0x" m " -m conntrack --ctdir ORIGINAL " \
                   "-j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff"

static char table[2][MAX_LINES][256];
static int  table_len[2];
static int  chain_exists[2], ovr_exists[2];
static int  restores, rci_calls, rci_absent, restored;

static int family_of(const char *cmd) {
    return strncmp(cmd, "ip6", 3) == 0;
}

static int in_chain(const char *line, const char *chain) {
    size_t n = strlen(chain);
    return strncmp(line, "-A ", 3) == 0 && strncmp(line + 3, chain, n) == 0 && line[3 + n] == ' ';
}

static void table_add(int fi, const char *line) {
    assert(table_len[fi] < MAX_LINES);
    snprintf(table[fi][table_len[fi]++], sizeof(table[fi][0]), "%s", line);
}

static void table_remove_at(int fi, int idx) {
    memmove(table[fi][idx], table[fi][idx + 1], (size_t)(table_len[fi] - idx - 1) * sizeof(table[fi][0]));
    table_len[fi]--;
}

static void table_remove_matching(int fi, const char *a, const char *b) {
    for (int i = 0; i < table_len[fi]; i++)
        if (strstr(table[fi][i], a) && (!b || strstr(table[fi][i], b))) table_remove_at(fi, i--);
}

static void chain_flush(int fi) {
    for (int i = 0; i < table_len[fi]; i++)
        if (in_chain(table[fi][i], CHAIN)) table_remove_at(fi, i--);
}

static void chain_drop(int fi) {
    chain_flush(fi);
    table_remove_matching(fi, "-j " CHAIN, NULL);
    chain_exists[fi] = 0;
}

static int chain_count(int fi, const char *chain) {
    int n = 0;
    for (int i = 0; i < table_len[fi]; i++) n += in_chain(table[fi][i], chain);
    return n;
}

static int chain_pos(int fi, const char *chain, const char *needle) {
    for (int i = 0, k = 0; i < table_len[fi]; i++) {
        if (!in_chain(table[fi][i], chain)) continue;
        if (strstr(table[fi][i], needle)) return k;
        k++;
    }
    return -1;
}

int __wrap_load_kmod(const char *name) {
    assert(strcmp(name, "xt_addrtype") == 0);
    return 0;
}

int __wrap_run_command_output(const char *cmd, char *const argv[], char *output, size_t size) {
    int fi = family_of(cmd);
    const char *op = argv[4], *chain = argv[5];
    output[0] = '\0';
    if (strcmp(op, "-S") == 0) {
        size_t off;
        if (strcmp(chain, CHAIN) == 0) {
            if (!chain_exists[fi]) {
                snprintf(output, size, "iptables: No chain/target/match by that name.\n");
                return 1;
            }
            off = (size_t)snprintf(output, size, "-N %s\n", chain);
        } else {
            off = (size_t)snprintf(output, size, "-P %s ACCEPT\n", chain);
        }
        for (int i = 0; i < table_len[fi]; i++)
            if (in_chain(table[fi][i], chain))
                off += (size_t)snprintf(output + off, size - off, "%s\n", table[fi][i]);
        return 0;
    }
    if (strcmp(chain, OVR) == 0) {
        assert(ovr_exists[fi]);
        if (strcmp(op, "-F") == 0) {
            table_remove_matching(fi, "-A " OVR " ", NULL);
        } else {
            assert(strcmp(op, "-X") == 0 && chain_count(fi, OVR) == 0);
            assert(chain_pos(fi, CHAIN, "-j " OVR) == -1);
            ovr_exists[fi] = 0;
        }
        return 0;
    }
    if (strcmp(op, "-F") == 0) {
        assert(chain_exists[fi]);
        chain_flush(fi);
        return 0;
    }
    if (strcmp(op, "-X") == 0) {
        assert(chain_exists[fi] && chain_count(fi, CHAIN) == 0);
        assert(chain_pos(fi, "PREROUTING", "-j " CHAIN) == -1);
        chain_exists[fi] = 0;
        return 0;
    }
    assert(strcmp(op, "-D") == 0);
    char line[256];
    int off = snprintf(line, sizeof(line), "-A");
    for (int i = 5; argv[i]; i++) off += snprintf(line + off, sizeof(line) - (size_t)off, " %s", argv[i]);
    for (int i = 0; i < table_len[fi]; i++)
        if (strcmp(table[fi][i], line) == 0) { table_remove_at(fi, i); return 0; }
    return 1;
}

int __wrap_run_command_stdin(const char *cmd, char *const argv[], const char *input, size_t len) {
    int fi = family_of(cmd);
    restores++;
    char buf[IPT_BATCH_SIZE];
    memcpy(buf, input, len);
    buf[len] = '\0';
    char *save;
    for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (strcmp(line, ":" CHAIN " - [0:0]") == 0) {
            if (chain_exists[fi]) chain_flush(fi);
            chain_exists[fi] = 1;
        } else if (strcmp(line, ":" OVR " - [0:0]") == 0) {
            table_remove_matching(fi, "-A " OVR " ", NULL);
            ovr_exists[fi] = 1;
        } else if (strncmp(line, "-A ", 3) == 0) {
            assert(!in_chain(line, CHAIN) || chain_exists[fi]);
            assert(!in_chain(line, OVR) || ovr_exists[fi]);
            assert(!strstr(line, "-j " OVR) || ovr_exists[fi]);
            table_add(fi, line);
        } else if (strncmp(line, "-D ", 3) == 0) {
            line[1] = 'A';
            int found = 0;
            for (int i = 0; i < table_len[fi] && !found; i++)
                if (strcmp(table[fi][i], line) == 0) { table_remove_at(fi, i); found = 1; }
            assert(found);
        }
    }
    return 0;
}

int rci_get_policy_mark(const char *name, char *mark, int mark_size) {
    rci_calls++;
    if (rci_absent) return RCI_MARK_ABSENT;
    snprintf(mark, (size_t)mark_size, "%s", strcmp(name, "RU") == 0 ? "ff1" : "ff2");
    return RCI_MARK_OK;
}

static void reset_counters(void) {
    restores = 0;
    rci_calls = 0;
}

static void assert_family_order(int fi, const char *ru, const char *hr) {
    char pat[128];
    assert(chain_exists[fi] && chain_count(fi, CHAIN) == 4);
    snprintf(pat, sizeof(pat), "--match-set %s dst -j CONNMARK --set-xmark 0xff1/", ru);
    assert(chain_pos(fi, CHAIN, pat) == 0);
    assert(chain_pos(fi, CHAIN, RESTORE("ff1")) == 1);
    snprintf(pat, sizeof(pat), "--match-set %s dst -j CONNMARK --set-xmark 0xff2/", hr);
    assert(chain_pos(fi, CHAIN, pat) == 2);
    assert(chain_pos(fi, CHAIN, RESTORE("ff2")) == 3);
    assert(chain_pos(fi, "PREROUTING", "-j " CHAIN) == chain_count(fi, "PREROUTING") - 1);
    assert(chain_pos(fi, "PREROUTING", "--match-set") == -1);
    assert(chain_pos(fi, CHAIN, "--restore-mark") == 1);
}

static void assert_override_family(int fi, const char *ru_jump, const char *hr_jump,
                                   const char *ru, const char *hr) {
    char pat[128];
    assert(ovr_exists[fi] && chain_count(fi, OVR) == 4);
    assert(chain_pos(fi, OVR, "-p tcp -m tcp --dport 53 -j RETURN") == 0);
    assert(chain_pos(fi, OVR, "-p udp -m udp --dport 53 -j RETURN") == 1);
    assert(chain_pos(fi, OVR, "--ctstate NEW -j PPE") == 2);
    assert(chain_pos(fi, OVR, "-j CONNMARK --set-xmark 0x0/0xffffffff") == 3);
    assert(chain_count(fi, CHAIN) == 6);
    assert(chain_pos(fi, CHAIN, ru_jump) == 0);
    assert(chain_pos(fi, CHAIN, hr_jump) == 1);
    snprintf(pat, sizeof(pat), "-m connmark --mark 0x0/0xffffffff -m set --match-set %s dst -j CONNMARK --set-xmark 0xff1/", ru);
    assert(chain_pos(fi, CHAIN, pat) == 2);
    assert(chain_pos(fi, CHAIN, RESTORE("ff1")) == 3);
    snprintf(pat, sizeof(pat), "-m connmark --mark 0x0/0xffffffff -m set --match-set %s dst -j CONNMARK --set-xmark 0xff2/", hr);
    assert(chain_pos(fi, CHAIN, pat) == 4);
    assert(chain_pos(fi, CHAIN, RESTORE("ff2")) == 5);
}

static void assert_override_order(void) {
    assert_override_family(0, OVR_JUMP("RU"), OVR_JUMP("HydraRoute"), "RU", "HydraRoute");
    assert_override_family(1, OVR_JUMP("RU6"), OVR_JUMP("HydraRoute6"), "RU6", "HydraRoute6");
}

static void assert_policy_order(void) {
    assert(chain_pos(0, "PREROUTING", "_NDM_") == 0);
    assert(chain_count(0, "PREROUTING") == 2 && chain_count(1, "PREROUTING") == 1);
    assert_family_order(0, "RU", "HydraRoute");
    assert_family_order(1, "RU6", "HydraRoute6");
}

int main(void) {
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    unified_target_t t[2];
    memset(t, 0, sizeof(t));
    strcpy(t[0].pair.ipv4, "RU");         strcpy(t[0].pair.ipv6, "RU6");
    strcpy(t[1].pair.ipv4, "HydraRoute"); strcpy(t[1].pair.ipv6, "HydraRoute6");

    table_add(0, "-A PREROUTING -j _NDM_HOTSPOT_PREROUTING_MANGL");

    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 2 && rci_calls == 2 && !restored);
    assert(chain_pos(0, "PREROUTING", JUMP) == 1);
    assert_policy_order();

    reset_counters();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 0 && rci_calls == 0 && !restored);
    assert_policy_order();

    reset_counters();
    table_remove_matching(0, "--match-set RU dst ", NULL);
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 1 && rci_calls == 1 && restored);
    assert_policy_order();

    reset_counters();
    table_remove_matching(1, RESTORE("ff1"), NULL);
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 1 && rci_calls == 0);
    assert_policy_order();

    reset_counters();
    chain_drop(0);
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 1 && rci_calls == 2 && restored);
    assert_policy_order();

    reset_counters();
    table_remove_matching(1, "-j " CHAIN, NULL);
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 1 && rci_calls == 0 && restored);
    assert_policy_order();

    reset_counters();
    rci_absent = 1;
    table_remove_matching(0, "--match-set RU dst ", NULL);
    table_remove_matching(0, RESTORE("ff1"), NULL);
    for (int pass = 0; pass < 2; pass++)
        assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == -1);
    assert(restores == 1 && rci_calls == 2 && !restored);
    assert(chain_count(0, CHAIN) == 2 && chain_count(1, CHAIN) == 2);

    reset_counters();
    rci_absent = 0;
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 2 && rci_calls == 1);
    assert_policy_order();

    cleanup_connmark_rules(0);
    assert(!chain_exists[0] && !chain_exists[1]);
    assert(table_len[0] == 1 && table_len[1] == 0);
    assert(chain_pos(0, "PREROUTING", "_NDM_") == 0);

    cfg.global_routing = 1;
    reset_counters();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 2 && rci_calls == 2);
    assert_override_order();

    reset_counters();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 0 && rci_calls == 0);
    assert_override_order();

    reset_counters();
    table_remove_matching(1, OVR_JUMP("HydraRoute6"), NULL);
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL, &restored) == 0);
    assert(restores == 1 && rci_calls == 0 && restored);
    assert_override_order();

    cleanup_connmark_rules(1);
    assert(!chain_exists[0] && !chain_exists[1] && !ovr_exists[0] && !ovr_exists[1]);
    assert(table_len[0] == 1 && table_len[1] == 0);

    puts("check_connmark: OK");
    return 0;
}
