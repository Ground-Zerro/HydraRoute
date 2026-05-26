#ifndef IPSET_NL_H
#define IPSET_NL_H

#include "hrneo.h"
#include <netinet/in.h>

#define IPSET_MAX_SETS 512

typedef struct {
    int fd;
    uint32_t seq;
    uint32_t pid;
    int set_has_timeout[256];
    uint32_t timeout_value[256];
    char set_names[IPSET_MAX_SETS][64];
    int set_count;
} ipset_manager_t;

int ipset_manager_init(ipset_manager_t *mgr);
void ipset_manager_close(ipset_manager_t *mgr);

int ipset_create(ipset_manager_t *mgr, const char *name, const char *type, int family, uint32_t timeout, uint32_t maxelem);
int ipset_flush(ipset_manager_t *mgr, const char *name);

int ipset_add_batch(ipset_manager_t *mgr, const char *set_name,
                    const parsed_cidr_t *entries, int count,
                    int with_timeout, int *new_count, int *new_indices);

int ipset_refresh_set_list(ipset_manager_t *mgr);
int ipset_set_exists(ipset_manager_t *mgr, const char *name);

void ipset_cache_timeout_for_set(ipset_manager_t *mgr, const char *name,
                                 int has_timeout, uint32_t timeout_val);

#endif
