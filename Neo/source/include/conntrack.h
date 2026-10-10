#ifndef CONNTRACK_H
#define CONNTRACK_H

#include "hrneo.h"
#include "l7_dispatch.h"

#define CT_PENDING_MAX 256

typedef int (*ct_heal_match_fn)(int family, const uint8_t *dst_ip);

typedef struct {
    int fd;
    int del_fd;
    parsed_cidr_t pending[CT_PENDING_MAX];
    int pending_count;
    int dump_family;
    int dump_heal;
    int heal_pending;
    int rescan;
    int deleted;
    ct_heal_match_fn heal_match;
} conntrack_mgr_t;

int  conntrack_mgr_init(conntrack_mgr_t *m);
void conntrack_mgr_close(conntrack_mgr_t *m);
void conntrack_flush_request(conntrack_mgr_t *m, const parsed_cidr_t *new_ips, int count);
void conntrack_heal_request(conntrack_mgr_t *m);
void conntrack_process(conntrack_mgr_t *m);
void conntrack_delete_conn(conntrack_mgr_t *m, const l7_conn_t *c);

#endif
