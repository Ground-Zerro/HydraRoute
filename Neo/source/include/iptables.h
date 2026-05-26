#ifndef IPTABLES_H
#define IPTABLES_H

#include "hrneo.h"
#include "rci.h"

typedef struct {
    ipset_pair_t pair;
    int is_interface;
    int fwmark;
} unified_target_t;

int apply_unified_connmark_rules(rci_client_t *rci, const unified_target_t *targets,
                                 int count, int global_routing);
int cleanup_connmark_rules(const ipset_pair_t *pairs, int count);

#endif
