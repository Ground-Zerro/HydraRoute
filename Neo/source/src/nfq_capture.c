#include "../include/nfq_capture.h"
#include "../include/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter.h>

#define NFQ_SUBSYS_QUEUE 3

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

static int nfq_send_msg(nfq_capture_t *cap, uint8_t *buf, int len) {
    struct sockaddr_nl peer;
    memset(&peer, 0, sizeof(peer));
    peer.nl_family = AF_NETLINK;
    return sendto(cap->fd, buf, len, 0,
                  (struct sockaddr *)&peer, sizeof(peer));
}

static int nfq_send_config_cmd(nfq_capture_t *cap, uint16_t qnum, uint8_t cmd, uint16_t pf) {
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFQ_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++cap->seq;
    nlh->nlmsg_pid = cap->portid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = AF_UNSPEC;
    nfgen[1] = NFNETLINK_V0;
    put_be16(nfgen + 2, qnum);

    int offset = NLMSG_HDRLEN + 4;

    struct nfqnl_msg_config_cmd cmd_pl;
    memset(&cmd_pl, 0, sizeof(cmd_pl));
    cmd_pl.command = cmd;
    put_be16((uint8_t *)&cmd_pl.pf, pf);
    offset += nla_put(buf + offset, NFQA_CFG_CMD, &cmd_pl, sizeof(cmd_pl));

    nlh->nlmsg_len = offset;

    if (nfq_send_msg(cap, buf, offset) < 0) {
        LOG_WARN("nfq send cmd %d: %s", cmd, strerror(errno));
        return -1;
    }

    uint8_t resp[512];
    int n = recv(cap->fd, resp, sizeof(resp), 0);
    if (n < 0) return -1;
    struct nlmsghdr *rnh = (struct nlmsghdr *)resp;
    if (rnh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)(resp + NLMSG_HDRLEN);
        if (err->error != 0) {
            LOG_WARN("nfq config cmd=%d pf=%u error=%d", cmd, pf, err->error);
            return err->error;
        }
    }
    return 0;
}

static int nfq_send_params(nfq_capture_t *cap, uint16_t qnum, uint8_t copy_mode, uint32_t copy_range) {
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFQ_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++cap->seq;
    nlh->nlmsg_pid = cap->portid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = AF_UNSPEC;
    nfgen[1] = NFNETLINK_V0;
    put_be16(nfgen + 2, qnum);

    int offset = NLMSG_HDRLEN + 4;

    struct nfqnl_msg_config_params params;
    memset(&params, 0, sizeof(params));
    put_be32((uint8_t *)&params.copy_range, copy_range);
    params.copy_mode = copy_mode;
    offset += nla_put(buf + offset, NFQA_CFG_PARAMS, &params, sizeof(params));

    nlh->nlmsg_len = offset;

    if (nfq_send_msg(cap, buf, offset) < 0) return -1;

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

static int nfq_send_u32_cfg(nfq_capture_t *cap, uint16_t qnum, uint16_t attr, uint32_t value) {
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFQ_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++cap->seq;
    nlh->nlmsg_pid = cap->portid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = AF_UNSPEC;
    nfgen[1] = NFNETLINK_V0;
    put_be16(nfgen + 2, qnum);

    int offset = NLMSG_HDRLEN + 4;

    uint8_t be_val[4];
    put_be32(be_val, value);
    offset += nla_put(buf + offset, attr, be_val, 4);

    nlh->nlmsg_len = offset;

    if (nfq_send_msg(cap, buf, offset) < 0) return -1;

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

static int nfq_send_flags(nfq_capture_t *cap, uint16_t qnum, uint32_t flags, uint32_t mask) {
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFQ_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++cap->seq;
    nlh->nlmsg_pid = cap->portid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = AF_UNSPEC;
    nfgen[1] = NFNETLINK_V0;
    put_be16(nfgen + 2, qnum);

    int offset = NLMSG_HDRLEN + 4;

    uint8_t be_flags[4], be_mask[4];
    put_be32(be_flags, flags);
    put_be32(be_mask, mask);
    offset += nla_put(buf + offset, NFQA_CFG_FLAGS, be_flags, 4);
    offset += nla_put(buf + offset, NFQA_CFG_MASK,  be_mask,  4);

    nlh->nlmsg_len = offset;

    if (nfq_send_msg(cap, buf, offset) < 0) return -1;

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

static int nfq_send_verdict(nfq_capture_t *cap, uint16_t qnum,
                            uint32_t packet_id, uint32_t verdict) {
    uint8_t buf[128];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFQ_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++cap->seq;
    nlh->nlmsg_pid = cap->portid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = AF_UNSPEC;
    nfgen[1] = NFNETLINK_V0;
    put_be16(nfgen + 2, qnum);

    int offset = NLMSG_HDRLEN + 4;

    struct nfqnl_msg_verdict_hdr vh;
    put_be32((uint8_t *)&vh.verdict, verdict);
    put_be32((uint8_t *)&vh.id, packet_id);
    offset += nla_put(buf + offset, NFQA_VERDICT_HDR, &vh, sizeof(vh));

    nlh->nlmsg_len = offset;

    return nfq_send_msg(cap, buf, offset);
}

static int nfq_parse_packet(const struct nlmsghdr *nh,
                            uint32_t *packet_id,
                            const uint8_t **payload, int *payload_len,
                            uint32_t *mark,
                            uint32_t *ifin, uint32_t *ifout) {
    *packet_id = 0;
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
        case NFQA_PACKET_HDR:
            if (body_len >= (int)sizeof(struct nfqnl_msg_packet_hdr)) {
                *packet_id = pntoh32(body);
            }
            break;
        case NFQA_PAYLOAD:
            *payload = body;
            *payload_len = body_len;
            break;
        case NFQA_MARK:
            if (body_len >= 4) *mark = pntoh32(body);
            break;
        case NFQA_IFINDEX_INDEV:
            if (body_len >= 4) *ifin = pntoh32(body);
            break;
        case NFQA_IFINDEX_OUTDEV:
            if (body_len >= 4) *ifout = pntoh32(body);
            break;
        }
        pos += aligned;
    }
    return 0;
}

int nfq_capture_init(nfq_capture_t *cap, uint16_t qnum,
                     nfq_packet_cb cb, void *user_data) {
    memset(cap, 0, sizeof(*cap));
    cap->qnum = qnum;
    cap->callback = cb;
    cap->user_data = user_data;

    cap->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (cap->fd < 0) {
        LOG_ERROR("nfq socket: %s", strerror(errno));
        return -1;
    }

    int rcvbuf = 1024 * 1024;
    setsockopt(cap->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    if (bind(cap->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG_ERROR("nfq bind: %s", strerror(errno));
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

    if (nfq_send_config_cmd(cap, 0, NFQNL_CFG_CMD_PF_UNBIND, AF_INET) < 0)
        goto fail;
    if (nfq_send_config_cmd(cap, 0, NFQNL_CFG_CMD_PF_BIND,   AF_INET) < 0)
        goto fail;
    if (nfq_send_config_cmd(cap, 0, NFQNL_CFG_CMD_PF_BIND,   AF_INET6) < 0)
        goto fail;

    if (nfq_send_config_cmd(cap, qnum, NFQNL_CFG_CMD_BIND, AF_UNSPEC) < 0)
        goto fail;

    if (nfq_send_params(cap, qnum, NFQNL_COPY_PACKET, NFQ_COPY_RANGE) < 0)
        goto fail;

    if (nfq_send_u32_cfg(cap, qnum, NFQA_CFG_QUEUE_MAXLEN, NFQ_QUEUE_MAXLEN) < 0)
        LOG_WARN("nfq queue maxlen failed (non-fatal)");

    uint32_t flags = NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO;
    if (nfq_send_flags(cap, qnum, flags, flags) < 0)
        LOG_WARN("nfq flags set failed (non-fatal)");

    return 0;

fail:
    close(cap->fd);
    cap->fd = -1;
    return -1;
}

int nfq_capture_fd(const nfq_capture_t *cap) {
    return cap->fd;
}

int nfq_capture_process(nfq_capture_t *cap) {
    for (;;) {
        ssize_t n = recv(cap->fd, cap->recv_buf, sizeof(cap->recv_buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                cap->stat_err++;
                LOG_WARN("nfq ENOBUFS — queue overflow");
                return 0;
            }
            LOG_WARN("nfq recv: %s", strerror(errno));
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
                    cap->stat_err++;
                    LOG_DEBUG("nfq nlmsgerr=%d", err->error);
                }
            } else if (subsys == NFQ_SUBSYS_QUEUE && msgtype == NFQNL_MSG_PACKET) {
                uint32_t pkt_id, mark, ifin, ifout;
                const uint8_t *payload;
                int payload_len;
                if (nfq_parse_packet(nh, &pkt_id, &payload, &payload_len,
                                     &mark, &ifin, &ifout) == 0) {
                    cap->stat_recv++;
                    if (payload && payload_len > 0 && cap->callback) {
                        cap->callback(payload, payload_len, mark, ifin, ifout,
                                      cap->user_data);
                    }
                    nfq_send_verdict(cap, cap->qnum, pkt_id, NF_ACCEPT);
                    cap->stat_pass++;
                }
            }
            nh = NLMSG_NEXT(nh, left);
        }
    }
}

void nfq_capture_close(nfq_capture_t *cap) {
    if (cap->fd < 0) return;
    nfq_send_config_cmd(cap, cap->qnum, NFQNL_CFG_CMD_UNBIND, AF_UNSPEC);
    close(cap->fd);
    cap->fd = -1;
}
