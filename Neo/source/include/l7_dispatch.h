#ifndef L7_DISPATCH_H
#define L7_DISPATCH_H

#include <stdint.h>

#define L7_TLS   1
#define L7_HTTP  2

struct tcp_reasm;

typedef struct {
    uint8_t  family;
    uint8_t  client_ip[16];
    uint8_t  server_ip[16];
    uint16_t client_port;
    uint16_t server_port;
} l7_conn_t;

void l7_dispatch_set_enable(int tls_enabled, int http_enabled);
void l7_dispatch_set_reasm (struct tcp_reasm *reasm);

void l7_dispatch_packet(const uint8_t *ip_pkt, int len,
                        uint32_t mark, uint32_t ifin, uint32_t ifout,
                        void *user);

extern void process_hostname_event_l7(const char *host, int proto,
                                      const l7_conn_t *conn);

#endif
