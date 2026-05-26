#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include "hrneo.h"
#include <stdint.h>

typedef void (*pkt_capture_cb)(const uint8_t *pkt, int pkt_len, void *user_data);

typedef struct {
    int fd4;
    int fd6;
    pkt_capture_cb callback;
    void *user_data;
    uint8_t recv_buf[65536];
} pkt_capture_t;

int  pkt_capture_init(pkt_capture_t *cap, pkt_capture_cb cb, void *user_data);
int  pkt_capture_process(pkt_capture_t *cap, int fd);
void pkt_capture_close(pkt_capture_t *cap);

#endif
