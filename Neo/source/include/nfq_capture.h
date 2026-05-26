#ifndef NFQ_CAPTURE_H
#define NFQ_CAPTURE_H

#include <stdint.h>
#include <stddef.h>

#define NFQ_RECV_BUF_SIZE  (128 * 1024)
#define NFQ_QUEUE_MAXLEN   1024
#define NFQ_COPY_RANGE     0xFFFF

typedef void (*nfq_packet_cb)(const uint8_t *ip_pkt, int len,
                              uint32_t mark, uint32_t ifindex_in,
                              uint32_t ifindex_out, void *user);

typedef struct {
    int            fd;
    uint16_t       qnum;
    uint32_t       seq;
    uint32_t       portid;
    nfq_packet_cb  callback;
    void          *user_data;
    uint64_t       stat_recv;
    uint64_t       stat_pass;
    uint64_t       stat_err;
    uint8_t        recv_buf[NFQ_RECV_BUF_SIZE];
} nfq_capture_t;

int  nfq_capture_init   (nfq_capture_t *cap, uint16_t qnum,
                         nfq_packet_cb cb, void *user_data);
int  nfq_capture_fd     (const nfq_capture_t *cap);
int  nfq_capture_process(nfq_capture_t *cap);
void nfq_capture_close  (nfq_capture_t *cap);

#endif
