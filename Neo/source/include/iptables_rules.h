#ifndef IPTABLES_RULES_H
#define IPTABLES_RULES_H

#include <stddef.h>

typedef struct {
    int exact_set_rule;
    int restore_rule;
    int conflicting_set_rule;
} connmark_rule_state_t;

int connmark_rule_state(const char *dump,
                        const char *ipset_name,
                        const char *mark_hex,
                        connmark_rule_state_t *state);

int connmark_format_set_rule(char *out,
                             size_t out_size,
                             const char *packet_condition,
                             const char *ipset_name,
                             const char *mark_hex);

int connmark_format_restore_rule(char *out,
                                 size_t out_size,
                                 const char *ipset_name);

#endif
