#ifndef IPTABLES_H
#define IPTABLES_H

#include "hrneo.h"
#include "rci.h"

#define IPT_DUMP_SIZE       65536
#define IPT_BATCH_SIZE      16384
#define IPT_MAX_RULE_ARGS   64

typedef struct {
    ipset_pair_t pair;
    int is_interface;
    int fwmark;
} unified_target_t;

int apply_unified_connmark_rules(const unified_target_t *targets, int count,
                                 const config_t *cfg, const char *l7_wan);
int cleanup_connmark_rules(const ipset_pair_t *pairs, int count);
void iptables_delete_rules_matching(const char *ipt_cmd, const char *chain,
                                    const char *needle1, const char *needle2);

#endif
