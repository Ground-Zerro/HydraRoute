#include "../include/packet_capture.h"
#include "../include/log.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <arpa/inet.h>

static struct sock_filter bpf_v4_dns[] = {
    { BPF_LD  | BPF_B   | BPF_ABS, 0, 0,   0   },
    { BPF_ALU | BPF_AND | BPF_K,   0, 0, 0x0F  },
    { BPF_ALU | BPF_LSH | BPF_K,   0, 0,   2   },
    { BPF_MISC | BPF_TAX,          0, 0,   0   },
    { BPF_LD  | BPF_B   | BPF_ABS, 0, 0,   0   },
    { BPF_ALU | BPF_AND | BPF_K,   0, 0, 0xF0  },
    { BPF_JMP | BPF_JEQ | BPF_K,   0, 5, 0x40  },
    { BPF_LD  | BPF_B   | BPF_ABS, 0, 0,   9   },
    { BPF_JMP | BPF_JEQ | BPF_K,   1, 0,  17   },
    { BPF_JMP | BPF_JEQ | BPF_K,   0, 2,   6   },
    { BPF_LD  | BPF_H   | BPF_IND, 0, 0,   0   },
    { BPF_JMP | BPF_JEQ | BPF_K,   1, 0,  53   },
    { BPF_RET | BPF_K,             0, 0,   0   },
    { BPF_RET | BPF_K,             0, 0, 65535  },
};

static struct sock_filter bpf_v6_dns[] = {
    { BPF_LD  | BPF_B   | BPF_ABS, 0, 0,   0   },
    { BPF_ALU | BPF_AND | BPF_K,   0, 0, 0xF0  },
    { BPF_JMP | BPF_JEQ | BPF_K,   0, 5, 0x60  },
    { BPF_LD  | BPF_B   | BPF_ABS, 0, 0,   6   },
    { BPF_JMP | BPF_JEQ | BPF_K,   1, 0,  17   },
    { BPF_JMP | BPF_JEQ | BPF_K,   0, 2,   6   },
    { BPF_LD  | BPF_H   | BPF_ABS, 0, 0,  40   },
    { BPF_JMP | BPF_JEQ | BPF_K,   1, 0,  53   },
    { BPF_RET | BPF_K,             0, 0,   0   },
    { BPF_RET | BPF_K,             0, 0, 65535  },
};

static int open_capture_socket(struct sock_filter *filter, int filter_len) {
    int fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) {
        LOG_ERROR("AF_PACKET socket: %s", strerror(errno));
        return -1;
    }

    int bufsize = SOCKET_READ_BUFFER;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    struct sock_fprog fprog;
    fprog.len    = (unsigned short)filter_len;
    fprog.filter = filter;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0)
        LOG_WARN("SO_ATTACH_FILTER: %s", strerror(errno));

    return fd;
}

int pkt_capture_init(pkt_capture_t *cap, pkt_capture_cb cb, void *user_data) {
    memset(cap, 0, sizeof(*cap));
    cap->fd4       = -1;
    cap->fd6       = -1;
    cap->callback  = cb;
    cap->user_data = user_data;

    cap->fd4 = open_capture_socket(bpf_v4_dns,
                                   (int)(sizeof(bpf_v4_dns) / sizeof(bpf_v4_dns[0])));
    if (cap->fd4 < 0)
        return -1;

    cap->fd6 = open_capture_socket(bpf_v6_dns,
                                   (int)(sizeof(bpf_v6_dns) / sizeof(bpf_v6_dns[0])));
    if (cap->fd6 < 0) {
        close(cap->fd4);
        cap->fd4 = -1;
        return -1;
    }

    LOG_INFO("Packet capture initialized (AF_PACKET fd4=%d fd6=%d)", cap->fd4, cap->fd6);
    return 0;
}

int pkt_capture_process(pkt_capture_t *cap, int fd) {
    struct sockaddr_ll sll;
    socklen_t sll_len = sizeof(sll);
    ssize_t n = recvfrom(fd, cap->recv_buf, sizeof(cap->recv_buf), 0,
                         (struct sockaddr *)&sll, &sll_len);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN)
            return 0;
        LOG_ERROR("pkt_capture recv: %s", strerror(errno));
        return -1;
    }
    if (n > 0 && cap->callback)
        cap->callback(cap->recv_buf, (int)n, cap->user_data);
    return 0;
}

void pkt_capture_close(pkt_capture_t *cap) {
    if (cap->fd4 >= 0) { close(cap->fd4); cap->fd4 = -1; }
    if (cap->fd6 >= 0) { close(cap->fd6); cap->fd6 = -1; }
}
