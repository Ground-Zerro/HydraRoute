#ifndef CONNTRACK_H
#define CONNTRACK_H

#include "hrneo.h"
#include "l7_dispatch.h"

/* Long-lived netlink (NETFILTER) socket for conntrack DUMP+DELETE.
 * Previously the fd was opened per call; now it lives across the
 * daemon's lifetime, removing a socket()/bind()/close() trip from
 * every DNS reply that yields a new IP. */
typedef struct {
    int fd;
    int del_fd;
} conntrack_mgr_t;

int  conntrack_mgr_init(conntrack_mgr_t *m);
void conntrack_mgr_close(conntrack_mgr_t *m);
void conntrack_flush_for_ips(conntrack_mgr_t *m, const parsed_cidr_t *new_ips, int count);
int  conntrack_delete_conn(conntrack_mgr_t *m, const l7_conn_t *c);

#endif
