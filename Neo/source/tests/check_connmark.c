#include "../include/iptables.h"
#include "../include/util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define MAX_LINES 32

static char table[2][MAX_LINES][256];
static int  table_len[2];
static int  restores, rci_calls, rci_absent;

static int family_of(const char *cmd) {
    return strncmp(cmd, "ip6", 3) == 0;
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

static int table_pos(int fi, const char *needle) {
    for (int i = 0; i < table_len[fi]; i++)
        if (strstr(table[fi][i], needle)) return i;
    return -1;
}

int __wrap_run_command_output(const char *cmd, char *const argv[], char *output, size_t size) {
    output[0] = '\0';
    int fi = family_of(cmd);
    size_t off = (size_t)snprintf(output, size, "-P PREROUTING ACCEPT\n");
    for (int i = 0; i < table_len[fi]; i++)
        off += (size_t)snprintf(output + off, size - off, "%s\n", table[fi][i]);
    return 0;
}

int __wrap_run_command_stdin(const char *cmd, char *const argv[], const char *input, size_t len) {
    int fi = family_of(cmd);
    restores++;
    char buf[IPT_BATCH_SIZE];
    memcpy(buf, input, len);
    buf[len] = '\0';
    char *save;
    for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (strncmp(line, "-A ", 3) == 0) {
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

static void assert_family_order(int fi, int base, const char *ru, const char *hr) {
    char pat[128];
    assert(table_len[fi] == base + 4);
    snprintf(pat, sizeof(pat), "--match-set %s dst -j CONNMARK --set-xmark 0xff1/", ru);
    assert(table_pos(fi, pat) == base);
    snprintf(pat, sizeof(pat), "--match-set %s dst -j CONNMARK --restore-mark", ru);
    assert(table_pos(fi, pat) == base + 1);
    snprintf(pat, sizeof(pat), "--match-set %s dst -j CONNMARK --set-xmark 0xff2/", hr);
    assert(table_pos(fi, pat) == base + 2);
    snprintf(pat, sizeof(pat), "--match-set %s dst -j CONNMARK --restore-mark", hr);
    assert(table_pos(fi, pat) == base + 3);
}

static void assert_policy_order(void) {
    assert(table_pos(0, "_NDM_") == 0);
    assert_family_order(0, 1, "RU", "HydraRoute");
    assert_family_order(1, 0, "RU6", "HydraRoute6");
}

int main(void) {
    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    unified_target_t t[2];
    memset(t, 0, sizeof(t));
    strcpy(t[0].pair.ipv4, "RU");         strcpy(t[0].pair.ipv6, "RU6");
    strcpy(t[1].pair.ipv4, "HydraRoute"); strcpy(t[1].pair.ipv6, "HydraRoute6");

    table_add(0, "-A PREROUTING -j _NDM_HOTSPOT_PREROUTING_MANGL");
    table_add(0, "-A PREROUTING -m set --match-set HydraRoute dst -j CONNMARK --set-xmark 0xff2/0xffffffff");
    table_add(0, "-A PREROUTING -m set --match-set HydraRoute dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff");
    table_add(0, "-A PREROUTING -m set --match-set RU dst -j CONNMARK --set-xmark 0xff1/0xffffffff");
    table_add(0, "-A PREROUTING -m set --match-set RU dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff");

    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(restores == 2 && rci_calls == 2);
    assert_policy_order();

    reset_counters();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(restores == 0 && rci_calls == 0);
    assert_policy_order();

    reset_counters();
    table_remove_matching(0, "--match-set RU dst ", NULL);
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(restores == 1 && rci_calls == 1);
    assert_policy_order();

    reset_counters();
    table_remove_matching(1, "--match-set RU6 dst ", "--restore-mark");
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(restores == 1 && rci_calls == 0);
    assert_policy_order();

    reset_counters();
    rci_absent = 1;
    table_remove_matching(0, "--match-set RU dst ", NULL);
    for (int pass = 0; pass < 2; pass++)
        assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == -1);
    assert(restores == 1 && rci_calls == 2);
    assert(table_len[0] == 3 && table_len[1] == 2);

    reset_counters();
    rci_absent = 0;
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(restores == 2 && rci_calls == 1);
    assert_policy_order();

    puts("check_connmark: OK");
    return 0;
}
