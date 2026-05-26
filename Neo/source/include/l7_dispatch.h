#ifndef L7_DISPATCH_H
#define L7_DISPATCH_H

#include <stdint.h>

#define L7_TLS   1
#define L7_HTTP  2

struct tcp_reasm;

void l7_dispatch_set_enable(int tls_enabled, int http_enabled);
void l7_dispatch_set_reasm (struct tcp_reasm *reasm);

void l7_dispatch_packet(const uint8_t *ip_pkt, int len,
                        uint32_t mark, uint32_t ifin, uint32_t ifout,
                        void *user);

void l7_dispatch_dump_stats(void);

extern void process_hostname_event_l7(const char *host, int proto,
                                      const uint8_t *daddr, int family);

#endif
