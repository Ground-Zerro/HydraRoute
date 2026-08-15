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
static const char *exact_global_pair =
    "-A PREROUTING -m connmark --mark 0x0/0xffffffff "
    "-m set --match-set nwg0 dst -j CONNMARK "
    "--set-xmark 0x3001/0xffffffff\n"
    "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
    "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";
static const char *conflicting_pair =
    "-A PREROUTING -m connmark --mark 0x0/0xffffffff "
    "-m set --match-set nwg0 dst -j CONNMARK "
    "--set-xmark 0x3002/0xffffffff\n";
static const char *restore_only =
    "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
    "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";
static const char *set_rule_without_connmark_match =
    "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
    "--set-xmark 0x3001/0xffffffff\n";
static const char *set_rule_with_partial_mark_mask =
    "-A PREROUTING -m connmark --mark 0x0 "
    "-m set --match-set nwg0 dst -j CONNMARK "
    "--set-xmark 0x3001/0xff\n";
static const char *set_rule_with_wrong_jump =
    "-A PREROUTING -m connmark --mark 0x0/0xffffffff "
    "-m set --match-set nwg0 dst -j MARK --set-xmark 0x3001/0xffffffff\n";
static const char *set_rule_with_wrong_packet_condition =
    "-A PREROUTING -m mark ! --mark 0x0/0xffffffff "
    "-m connmark --mark 0x0/0xffffffff "
    "-m set --match-set nwg0 dst -j CONNMARK "
    "--set-xmark 0x3001/0xffffffff\n";
static const char *restore_with_partial_masks =
    "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
    "--restore-mark --nfmask 0xff --ctmask 0xffffffff\n";
static const char *exact_pair_with_implicit_connmark_mask =
    "-A PREROUTING -m connmark --mark 0x0 "
    "-m set --match-set nwg0 dst -j CONNMARK "
    "--set-xmark 0x3001/0xffffffff\n"
    "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
    "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";
static const char *exact_pair_with_source_predicate =
    "-A PREROUTING -s 192.0.2.0/24 -m connmark --mark 0x0/0xffffffff "
    "-m set --match-set nwg0 dst -j CONNMARK "
    "--set-xmark 0x3001/0xffffffff\n"
    "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
    "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";

static int check_state(const char *name, const char *dump, const char *set,
                       const char *mark, int exact, int restore, int conflict) {
    connmark_rule_state_t state;
    if (connmark_rule_state(dump, set, mark, &state) != 0 ||
        state.exact_set_rule != exact || state.restore_rule != restore ||
        (state.conflicting_set_rule || state.conflicting_restore_rule) != conflict) {
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
        {"action-pair", {.exact_set_rule = 0}, CONNMARK_RESTORE_PAIR},
        {"action-restore-only", {.exact_set_rule = 1}, CONNMARK_RESTORE_ONLY},
        {"action-none", {.exact_set_rule = 1, .restore_rule = 1}, CONNMARK_RESTORE_NONE},
        {"action-conflict", {.conflicting_set_rule = 1}, CONNMARK_RESTORE_DEFER},
        {"action-restore-before-set", {.restore_rule = 1}, CONNMARK_RESTORE_DEFER},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (connmark_restore_action(&cases[i].state) != cases[i].expected) {
            fprintf(stderr, "%s\n", cases[i].name);
            return 1;
        }
    }
    return 0;
}

static int check_semantic_matching(void) {
    int failed = 0;
    failed |= check_state("missing-connmark-match", set_rule_without_connmark_match,
                          "nwg0", "3001", 0, 0, 1);
    failed |= check_state("partial-mark-mask", set_rule_with_partial_mark_mask,
                          "nwg0", "3001", 0, 0, 1);
    failed |= check_state("wrong-jump", set_rule_with_wrong_jump,
                          "nwg0", "3001", 0, 0, 1);
    failed |= check_state("wrong-packet-condition", set_rule_with_wrong_packet_condition,
                          "nwg0", "3001", 0, 0, 1);
    failed |= check_state("partial-restore-masks", restore_with_partial_masks,
                          "nwg0", "3001", 0, 0, 1);
    return failed;
}

static int check_expected_packet_conditions(void) {
    static const char *global_pair =
        "-A PREROUTING -m connmark --mark 0x0 "
        "-m set --match-set nwg0 dst -j CONNMARK "
        "--set-xmark 0x3001/0xffffffff\n"
        "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
        "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";
    static const char *non_global_condition =
        "-m mark ! --mark 0xffffaa0/0xffffff0 ";
    connmark_rule_state_t state;

    if (connmark_rule_state_for_condition(global_pair, "nwg0", "3001", "",
                                          &state) != 0 ||
        connmark_restore_action(&state) != CONNMARK_RESTORE_NONE) {
        fprintf(stderr, "expected-global-condition\n");
        return 1;
    }
    if (connmark_rule_state_for_condition(exact_pair, "nwg0", "3001",
                                          non_global_condition, &state) != 0 ||
        connmark_restore_action(&state) != CONNMARK_RESTORE_NONE) {
        fprintf(stderr, "expected-non-global-condition\n");
        return 1;
    }
    if (connmark_rule_state_for_condition(global_pair, "nwg0", "3001",
                                          non_global_condition, &state) != 0 ||
        connmark_restore_action(&state) != CONNMARK_RESTORE_DEFER) {
        fprintf(stderr, "reject-global-as-non-global\n");
        return 1;
    }
    if (connmark_rule_state_for_condition(exact_pair, "nwg0", "3001", "",
                                          &state) != 0 ||
        connmark_restore_action(&state) != CONNMARK_RESTORE_DEFER) {
        fprintf(stderr, "reject-non-global-as-explicit-global\n");
        return 1;
    }
    return 0;
}

static int check_authoritative_repair_decision(void) {
    connmark_rule_state_t state;
    if (check_state("extra-source-predicate", exact_pair_with_source_predicate,
                    "nwg0", "3001", 0, 1, 1) != 0)
        return 1;
    if (connmark_rule_state_for_condition(exact_pair_with_source_predicate,
                                          "nwg0", "3001", "", &state) != 0 ||
        connmark_restore_action(&state) != CONNMARK_RESTORE_DEFER) {
        fprintf(stderr, "authoritative-repair-extra-source-predicate\n");
        return 1;
    }
    return 0;
}

static int check_multi_target_ordering(void) {
    static const char *lower_target_survives =
        "-A PREROUTING -m connmark --mark 0x0 "
        "-m set --match-set nwg1 dst -j CONNMARK "
        "--set-xmark 0x3002/0xffffffff\n"
        "-A PREROUTING -m set --match-set nwg1 dst -j CONNMARK "
        "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";
    static const char *reverse_target_order =
        "-A PREROUTING -m connmark --mark 0x0 "
        "-m set --match-set nwg1 dst -j CONNMARK "
        "--set-xmark 0x3002/0xffffffff\n"
        "-A PREROUTING -m set --match-set nwg1 dst -j CONNMARK "
        "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n"
        "-A PREROUTING -m connmark --mark 0x0 "
        "-m set --match-set nwg0 dst -j CONNMARK "
        "--set-xmark 0x3001/0xffffffff\n"
        "-A PREROUTING -m set --match-set nwg0 dst -j CONNMARK "
        "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n";
    static const connmark_restore_target_t ordered_targets[] = {
        {"nwg0", "3001", ""},
        {"nwg1", "3002", ""},
    };
    if (connmark_restore_order_safe(lower_target_survives,
                                    ordered_targets,
                                    sizeof(ordered_targets) /
                                        sizeof(ordered_targets[0])) != 1) {
        fprintf(stderr, "defer-missing-higher-priority-target\n");
        return 1;
    }
    if (connmark_restore_order_safe(reverse_target_order, ordered_targets,
                                    sizeof(ordered_targets) /
                                        sizeof(ordered_targets[0])) != 1) {
        fprintf(stderr, "defer-reversed-surviving-targets\n");
        return 1;
    }
    if (connmark_restore_order_safe(empty_dump, ordered_targets,
                                    sizeof(ordered_targets) /
                                        sizeof(ordered_targets[0])) != 0) {
        fprintf(stderr, "allow-full-rebuild-in-order\n");
        return 1;
    }
    if (connmark_restore_order_safe(exact_global_pair, ordered_targets,
                                    sizeof(ordered_targets) /
                                        sizeof(ordered_targets[0])) != 0) {
        fprintf(stderr, "allow-missing-lower-priority-target\n");
        return 1;
    }
    return 0;
}

int main(void) {
    int failed = 0;
    failed |= check_state("empty-state", empty_dump, "nwg0", "3001", 0, 0, 0);
    failed |= check_state("exact-pair", exact_pair, "nwg0", "3001", 1, 1, 0);
    failed |= check_state("optional-mark-prefix", exact_pair, "nwg0", "0x3001", 1, 1, 0);
    failed |= check_state("conflicting-mark", conflicting_pair, "nwg0", "3001", 0, 0, 1);
    failed |= check_state("restore-only", restore_only, "nwg0", "3001", 0, 1, 0);
    failed |= check_state("exact-set-name", conflicting_pair, "nwg01", "3001", 0, 0, 0);
    failed |= check_renderers();
    failed |= check_restore_actions();
    failed |= check_semantic_matching();
    failed |= check_state("implicit-connmark-mask",
                          exact_pair_with_implicit_connmark_mask,
                          "nwg0", "3001", 1, 1, 0);
    failed |= check_expected_packet_conditions();
    failed |= check_authoritative_repair_decision();
    failed |= check_multi_target_ordering();

    if (failed)
        return 1;

    puts("check_fast_restore: ok");
    return 0;
}
