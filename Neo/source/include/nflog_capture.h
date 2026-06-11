#ifndef NFLOG_CAPTURE_H
#define NFLOG_CAPTURE_H

#include <stdint.h>
#include <stddef.h>

#define NFLOG_RECV_BUF_SIZE  (128 * 1024)
#define NFLOG_NLBUFSIZ       (128 * 1024)
#define NFLOG_COPY_RANGE     0xFFFF

typedef void (*nflog_packet_cb)(const uint8_t *ip_pkt, int len,
                                uint32_t mark, uint32_t ifindex_in,
                                uint32_t ifindex_out, void *user);

typedef struct {
    int             fd;
    uint16_t        group;
    uint32_t        seq;
    uint32_t        portid;
    nflog_packet_cb callback;
    void           *user_data;
    uint8_t         recv_buf[NFLOG_RECV_BUF_SIZE];
} nflog_capture_t;

int  nflog_capture_init   (nflog_capture_t *cap, uint16_t group,
                           nflog_packet_cb cb, void *user_data);
int  nflog_capture_fd     (const nflog_capture_t *cap);
int  nflog_capture_process(nflog_capture_t *cap);
void nflog_capture_close  (nflog_capture_t *cap);

#endif
