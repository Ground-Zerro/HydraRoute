#ifndef GEODAT_H
#define GEODAT_H

#include "hrneo.h"
#include "ipset_nl.h"

int parse_geosite_rules(const char *watchlist_path,
                        geosite_rule_t *rules, int max_rules);

int build_geosite_domain_map(const char (*file_paths)[512], int file_count,
                             const geosite_rule_t *rules, int rule_count,
                             domain_hashtable_t *ht);

int add_cidr_to_ipsets(ipset_manager_t *mgr, const char *cidr_path,
                       const ipset_pair_t *pairs, int pair_count,
                       int enable_timeout, int timeout,
                       const char (*geoip_files)[512], int geoip_count,
                       uint32_t maxelem);

#endif
