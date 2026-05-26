#ifndef WATCHLIST_H
#define WATCHLIST_H

#include "hrneo.h"
#include <stddef.h>

int parse_watchlist(const char *path, domain_hashtable_t *ht);
int get_unique_names(const domain_hashtable_t *ht, char names[][64], int max_names);
void sort_policies(char names[][64], int count, const char order[][64], int order_count);
int parse_cidr_policy_headers(const char *path, char names[][64], int max_names);

/* Generic line-visitor for domain.conf-style entries `domain1,domain2/Target`.
 * on_target is called once per non-empty/non-comment line; if it returns 0 the
 * line's domains are skipped. on_domain is called for every non-empty,
 * non-geosite: domain on the line (already lowercased). Either visitor may be
 * NULL. Returns 0 on success, -1 if the file cannot be opened. */
typedef int  (*watchlist_target_fn)(const char *target, void *user);
typedef void (*watchlist_domain_fn)(const char *target, const char *domain,
                                    size_t domain_len, void *user);
int parse_watchlist_lines(const char *path,
                          watchlist_target_fn on_target,
                          watchlist_domain_fn on_domain,
                          void *user);

const char *match_domain_with_cname(const domain_hashtable_t *ht,
                                    const char (*policy_order)[64], int order_count,
                                    const char *domain,
                                    const cname_entry_t *cnames, int cname_count,
                                    const char **matched_domain);

#endif
