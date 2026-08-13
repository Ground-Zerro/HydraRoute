#include "../include/iptables_rules.h"
#include <stdio.h>
#include <string.h>

static const char *empty_dump = "-P PREROUTING ACCEPT\n";
static const char *exact_pair =
    "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 "
    "-m connmark --mark 0x0/0xffffffff -m set --match-set nwg0 dst "
    "-j CONNMARK --set-xmark 0x3001/0xffffffff\n"
    "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
    "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";
static const char *conflicting_pair =
    "-A PREROUTING -m connmark --mark 0x0/0xffffffff "
    "-m set --match-set nwg0 dst -j CONNMARK "
    "--set-xmark 0x3002/0xffffffff\n";
static const char *restore_only =
    "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
    "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";

static int check_state(const char *name, const char *dump, const char *set,
                       const char *mark, int exact, int restore, int conflict) {
    connmark_rule_state_t state;
    if (connmark_rule_state(dump, set, mark, &state) != 0 ||
        state.exact_set_rule != exact || state.restore_rule != restore ||
        state.conflicting_set_rule != conflict) {
        fprintf(stderr, "%s\n", name);
        return 1;
    }
    return 0;
}

static int check_renderers(void) {
    char out[512];
    const char *global_set =
        "-A PREROUTING -m connmark --mark 0x0/0xffffffff "
        "-m set --match-set nwg0 dst -j CONNMARK "
        "--set-xmark 0x3001/0xffffffff\n";
    const char *non_global_set =
        "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 "
        "-m connmark --mark 0x0/0xffffffff "
        "-m set --match-set nwg0 dst -j CONNMARK "
        "--set-xmark 0x3001/0xffffffff\n";
    const char *restore =
        "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
        "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";

    if (connmark_format_set_rule(out, sizeof(out), "", "nwg0", "3001") != 0 ||
        strcmp(out, global_set) != 0) {
        fprintf(stderr, "render-global-set\n");
        return 1;
    }
    if (connmark_format_set_rule(out, sizeof(out),
                                 "-m mark ! --mark 0xffffaa0/0xffffff0 ",
                                 "nwg0", "0x3001") != 0 ||
        strcmp(out, non_global_set) != 0) {
        fprintf(stderr, "render-non-global-set\n");
        return 1;
    }
    if (connmark_format_restore_rule(out, sizeof(out), "nwg0") != 0 ||
        strcmp(out, restore) != 0) {
        fprintf(stderr, "render-restore\n");
        return 1;
    }
    return 0;
}

static int check_restore_actions(void) {
    static const struct {
        const char *name;
        connmark_rule_state_t state;
        connmark_restore_action_t expected;
    } cases[] = {
        {"action-pair", {0, 0, 0}, CONNMARK_RESTORE_PAIR},
        {"action-restore-only", {1, 0, 0}, CONNMARK_RESTORE_ONLY},
        {"action-none", {1, 1, 0}, CONNMARK_RESTORE_NONE},
        {"action-conflict", {0, 0, 1}, CONNMARK_RESTORE_DEFER},
        {"action-restore-before-set", {0, 1, 0}, CONNMARK_RESTORE_DEFER},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (connmark_restore_action(&cases[i].state) != cases[i].expected) {
            fprintf(stderr, "%s\n", cases[i].name);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    if (check_state("empty-state", empty_dump, "nwg0", "3001", 0, 0, 0) != 0)
        return 1;
    if (check_state("exact-pair", exact_pair, "nwg0", "3001", 1, 1, 0) != 0)
        return 1;
    if (check_state("optional-mark-prefix", exact_pair, "nwg0", "0x3001", 1, 1, 0) != 0)
        return 1;
    if (check_state("conflicting-mark", conflicting_pair, "nwg0", "3001", 0, 0, 1) != 0)
        return 1;
    if (check_state("restore-only", restore_only, "nwg0", "3001", 0, 1, 0) != 0)
        return 1;
    if (check_state("exact-set-name", conflicting_pair, "nwg01", "3001", 0, 0, 0) != 0)
        return 1;
    if (check_renderers() != 0)
        return 1;
    if (check_restore_actions() != 0)
        return 1;

    puts("check_fast_restore: ok");
    return 0;
}
