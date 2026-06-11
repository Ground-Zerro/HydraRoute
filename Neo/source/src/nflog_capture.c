#include "../include/nflog_capture.h"
#include "../include/log.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#define NFLOG_SUBSYS           4

#define NFULNL_MSG_PACKET      0
#define NFULNL_MSG_CONFIG      1

#define NFULNL_CFG_CMD_BIND      1
#define NFULNL_CFG_CMD_UNBIND    2
#define NFULNL_CFG_CMD_PF_BIND   3
#define NFULNL_CFG_CMD_PF_UNBIND 4

#define NFULA_CFG_CMD          1
#define NFULA_CFG_MODE         2
#define NFULA_CFG_NLBUFSIZ     3

#define NFULNL_COPY_PACKET     2

#define NFULA_MARK             2
#define NFULA_IFINDEX_INDEV    4
#define NFULA_IFINDEX_OUTDEV   5
#define NFULA_PAYLOAD          9

struct nful_msg_config_cmd {
    uint8_t command;
} __attribute__((packed));

struct nful_msg_config_mode {
    uint32_t copy_range;
    uint8_t  copy_mode;
    uint8_t  _pad;
} __attribute__((packed));

static inline uint32_t pntoh32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static inline void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xFF);
}
static inline void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v & 0xFF);
}

static int nla_put(uint8_t *buf, uint16_t type, const void *data, uint16_t data_len) {
    uint16_t nla_len = NLA_HDRLEN + data_len;
    memcpy(buf, &nla_len, 2);
    memcpy(buf + 2, &type, 2);
    if (data_len) memcpy(buf + NLA_HDRLEN, data, data_len);
    return NLA_ALIGN(nla_len);
}

static int nflog_send_msg(nflog_capture_t *cap, uint8_t *buf, int len) {
    struct sockaddr_nl peer;
    memset(&peer, 0, sizeof(peer));
    peer.nl_family = AF_NETLINK;
    return sendto(cap->fd, buf, len, 0,
                  (struct sockaddr *)&peer, sizeof(peer));
}

static int nflog_send_config(nflog_capture_t *cap, uint16_t group,
                             uint8_t family, const uint8_t *attrs, int attrs_len) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFLOG_SUBSYS << 8) | NFULNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++cap->seq;
    nlh->nlmsg_pid = cap->portid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = family;
    nfgen[1] = NFNETLINK_V0;
    put_be16(nfgen + 2, group);

    int offset = NLMSG_HDRLEN + 4;
    if (attrs_len > 0 && offset + attrs_len <= (int)sizeof(buf)) {
        memcpy(buf + offset, attrs, attrs_len);
        offset += attrs_len;
    }

    nlh->nlmsg_len = offset;

    if (nflog_send_msg(cap, buf, offset) < 0) {
        LOG_WARN("nflog send config: %s", strerror(errno));
        return -1;
    }

    uint8_t resp[512];
    int n = recv(cap->fd, resp, sizeof(resp), 0);
    if (n < 0) return -1;
    struct nlmsghdr *rnh = (struct nlmsghdr *)resp;
    if (rnh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)(resp + NLMSG_HDRLEN);
        return err->error;
    }
    return 0;
}

static int nflog_cfg_cmd(nflog_capture_t *cap, uint16_t group,
                         uint8_t family, uint8_t command) {
    uint8_t attrs[64];
    struct nful_msg_config_cmd cmd = { command };
    int len = nla_put(attrs, NFULA_CFG_CMD, &cmd, sizeof(cmd));
    return nflog_send_config(cap, group, family, attrs, len);
}

static int nflog_cfg_mode(nflog_capture_t *cap, uint16_t group,
                          uint32_t copy_range, uint32_t nlbufsiz) {
    uint8_t attrs[64];
    int len = 0;

    struct nful_msg_config_mode mode;
    memset(&mode, 0, sizeof(mode));
    put_be32((uint8_t *)&mode.copy_range, copy_range);
    mode.copy_mode = NFULNL_COPY_PACKET;
    len += nla_put(attrs + len, NFULA_CFG_MODE, &mode, sizeof(mode));

    uint8_t be_buf[4];
    put_be32(be_buf, nlbufsiz);
    len += nla_put(attrs + len, NFULA_CFG_NLBUFSIZ, be_buf, 4);

    return nflog_send_config(cap, group, 0, attrs, len);
}

static int nflog_parse_packet(const struct nlmsghdr *nh,
                              const uint8_t **payload, int *payload_len,
                              uint32_t *mark,
                              uint32_t *ifin, uint32_t *ifout) {
    *payload = NULL;
    *payload_len = 0;
    *mark = 0;
    *ifin = 0;
    *ifout = 0;

    int total = (int)nh->nlmsg_len;
    if (total < (int)(NLMSG_HDRLEN + 4)) return -1;

    const uint8_t *attrs = (const uint8_t *)nh + NLMSG_HDRLEN + 4;
    int attrs_len = total - NLMSG_HDRLEN - 4;

    int pos = 0;
    while (pos + NLA_HDRLEN <= attrs_len) {
        uint16_t nla_len, nla_type;
        memcpy(&nla_len, attrs + pos, 2);
        memcpy(&nla_type, attrs + pos + 2, 2);
        uint16_t a_type = nla_type & ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER);
        if (nla_len < NLA_HDRLEN) break;
        int aligned = NLA_ALIGN(nla_len);
        if (pos + aligned > attrs_len) break;

        const uint8_t *body = attrs + pos + NLA_HDRLEN;
        int body_len = nla_len - NLA_HDRLEN;

        switch (a_type) {
        case NFULA_PAYLOAD:
            *payload = body;
            *payload_len = body_len;
            break;
        case NFULA_MARK:
            if (body_len >= 4) *mark = pntoh32(body);
            break;
        case NFULA_IFINDEX_INDEV:
            if (body_len >= 4) *ifin = pntoh32(body);
            break;
        case NFULA_IFINDEX_OUTDEV:
            if (body_len >= 4) *ifout = pntoh32(body);
            break;
        }
        pos += aligned;
    }
    return 0;
}

int nflog_capture_init(nflog_capture_t *cap, uint16_t group,
                       nflog_packet_cb cb, void *user_data) {
    memset(cap, 0, sizeof(*cap));
    cap->group = group;
    cap->callback = cb;
    cap->user_data = user_data;

    cap->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (cap->fd < 0) {
        LOG_ERROR("nflog socket: %s", strerror(errno));
        return -1;
    }

    int rcvbuf = 1024 * 1024;
    setsockopt(cap->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    if (bind(cap->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG_ERROR("nflog bind: %s", strerror(errno));
        close(cap->fd);
        cap->fd = -1;
        return -1;
    }

    socklen_t sl = sizeof(sa);
    if (getsockname(cap->fd, (struct sockaddr *)&sa, &sl) == 0) {
        cap->portid = sa.nl_pid;
    } else {
        cap->portid = (uint32_t)getpid();
    }

    cap->seq = 1;

    nflog_cfg_cmd(cap, 0, AF_INET,  NFULNL_CFG_CMD_PF_UNBIND);
    nflog_cfg_cmd(cap, 0, AF_INET,  NFULNL_CFG_CMD_PF_BIND);
    nflog_cfg_cmd(cap, 0, AF_INET6, NFULNL_CFG_CMD_PF_BIND);

    if (nflog_cfg_cmd(cap, group, AF_UNSPEC, NFULNL_CFG_CMD_BIND) != 0) {
        LOG_ERROR("nflog bind group %u failed", group);
        close(cap->fd);
        cap->fd = -1;
        return -1;
    }

    if (nflog_cfg_mode(cap, group, NFLOG_COPY_RANGE, NFLOG_NLBUFSIZ) != 0) {
        LOG_ERROR("nflog set mode group %u failed", group);
        close(cap->fd);
        cap->fd = -1;
        return -1;
    }

    return 0;
}

int nflog_capture_fd(const nflog_capture_t *cap) {
    return cap->fd;
}

int nflog_capture_process(nflog_capture_t *cap) {
    for (;;) {
        ssize_t n = recv(cap->fd, cap->recv_buf, sizeof(cap->recv_buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                LOG_WARN("nflog ENOBUFS — log buffer overflow, some hosts skipped");
                return 0;
            }
            LOG_WARN("nflog recv: %s", strerror(errno));
            return -1;
        }
        if (n == 0) return 0;

        struct nlmsghdr *nh = (struct nlmsghdr *)cap->recv_buf;
        ssize_t left = n;
        while (left >= (ssize_t)NLMSG_HDRLEN && NLMSG_OK(nh, (unsigned)left)) {
            uint8_t subsys = (uint8_t)(nh->nlmsg_type >> 8);
            uint8_t msgtype = (uint8_t)(nh->nlmsg_type & 0xFF);

            if (nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
                if (err->error != 0) {
                    LOG_DEBUG("nflog nlmsgerr=%d", err->error);
                }
            } else if (subsys == NFLOG_SUBSYS && msgtype == NFULNL_MSG_PACKET) {
                uint32_t mark, ifin, ifout;
                const uint8_t *payload;
                int payload_len;
                if (nflog_parse_packet(nh, &payload, &payload_len,
                                       &mark, &ifin, &ifout) == 0) {
                    if (payload && payload_len > 0 && cap->callback) {
                        cap->callback(payload, payload_len, mark, ifin, ifout,
                                      cap->user_data);
                    }
                }
            }
            nh = NLMSG_NEXT(nh, left);
        }
    }
}

void nflog_capture_close(nflog_capture_t *cap) {
    if (cap->fd < 0) return;
    nflog_cfg_cmd(cap, cap->group, AF_UNSPEC, NFULNL_CFG_CMD_UNBIND);
    close(cap->fd);
    cap->fd = -1;
}
