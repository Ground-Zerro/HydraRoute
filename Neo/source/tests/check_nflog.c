#include "../include/nflog_capture.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/netlink.h>

static int mode_msgs;
static uint32_t nlbufsiz, timeout_cs, qthresh;

static uint32_t be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

int __wrap_socket(int domain, int type, int protocol) {
    return open("/dev/null", O_RDWR);
}

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    return 0;
}

ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *addr, socklen_t alen) {
    const struct nlmsghdr *nh = buf;
    const uint8_t *a = (const uint8_t *)buf + NLMSG_HDRLEN + 4;
    int left = (int)nh->nlmsg_len - NLMSG_HDRLEN - 4, has_mode = 0;
    while (left >= NLA_HDRLEN) {
        uint16_t l, t;
        memcpy(&l, a, 2);
        memcpy(&t, a + 2, 2);
        if (t == 2) has_mode = 1;
        if (t == 3) nlbufsiz = be32(a + NLA_HDRLEN);
        if (t == 4) timeout_cs = be32(a + NLA_HDRLEN);
        if (t == 5) qthresh = be32(a + NLA_HDRLEN);
        left -= NLA_ALIGN(l);
        a += NLA_ALIGN(l);
    }
    mode_msgs += has_mode;
    return (ssize_t)len;
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    struct nlmsghdr *nh = buf;
    struct nlmsgerr *e = (struct nlmsgerr *)((uint8_t *)buf + NLMSG_HDRLEN);
    memset(buf, 0, NLMSG_HDRLEN + sizeof(*e));
    nh->nlmsg_type = NLMSG_ERROR;
    nh->nlmsg_len = NLMSG_HDRLEN + sizeof(*e);
    return (ssize_t)nh->nlmsg_len;
}

int main(void) {
    static nflog_capture_t cap;
    assert(nflog_capture_init(&cap, 210, NULL, NULL) == 0);
    assert(mode_msgs == 1);
    assert(qthresh == 8 && timeout_cs == 2 && nlbufsiz == 16384);
    nflog_capture_close(&cap);
    puts("check_nflog: OK");
    return 0;
}
