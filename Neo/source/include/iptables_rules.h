#ifndef IPTABLES_RULES_H
#define IPTABLES_RULES_H

#include <stddef.h>

typedef struct {
    int exact_set_rule;
    int restore_rule;
    int conflicting_set_rule;
    int conflicting_restore_rule;
    int set_rule_index;
    int restore_rule_index;
} connmark_rule_state_t;

int connmark_rule_state(const char *dump,
                        const char *ipset_name,
                        const char *mark_hex,
                        connmark_rule_state_t *state);

int connmark_rule_state_for_condition(const char *dump,
                                      const char *ipset_name,
                                      const char *mark_hex,
                                      const char *packet_condition,
                                      connmark_rule_state_t *state);

int connmark_format_set_rule(char *out,
                             size_t out_size,
                             const char *packet_condition,
                             const char *ipset_name,
                             const char *mark_hex);

int connmark_format_restore_rule(char *out,
                                 size_t out_size,
                                 const char *ipset_name);

typedef enum {
    CONNMARK_RESTORE_NONE = 0,
    CONNMARK_RESTORE_PAIR,
    CONNMARK_RESTORE_ONLY,
    CONNMARK_RESTORE_DEFER
} connmark_restore_action_t;

connmark_restore_action_t
connmark_restore_action(const connmark_rule_state_t *state);

typedef struct {
    const char *ipset_name;
    const char *mark_hex;
    const char *packet_condition;
} connmark_restore_target_t;

/* 0: append-only restore preserves order, 1: defer to authoritative reconcile. */
int connmark_restore_order_safe(const char *dump,
                                const connmark_restore_target_t *targets,
                                size_t target_count);

#endif
