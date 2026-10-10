#include "../include/conntrack.h"
#include "../include/log.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CT_MSG_TYPE_GET    ((CT_NFNL_SUBSYS << 8) | CT_MSG_GET)
#define CT_MSG_TYPE_DELETE ((CT_NFNL_SUBSYS << 8) | CT_MSG_DELETE)
#define CT_RECV_BUDGET 8

int conntrack_mgr_init(conntrack_mgr_t *m) {
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    m->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_NETFILTER);
    if (m->fd < 0) {
        LOG_ERROR("conntrack socket: %s", strerror(errno));
        return -1;
    }
    bind(m->fd, (struct sockaddr *)&sa, sizeof(sa));

    int rcvbuf = 1 << 20;
    setsockopt(m->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    m->del_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (m->del_fd < 0) {
        LOG_ERROR("conntrack delete socket: %s", strerror(errno));
        close(m->fd);
        m->fd = -1;
        return -1;
    }
    bind(m->del_fd, (struct sockaddr *)&sa, sizeof(sa));

    m->pending_count = 0;
    m->dump_family = 0;
    m->dump_heal = 0;
    m->heal_pending = 0;
    m->rescan = 0;
    m->deleted = 0;
    return 0;
}

void conntrack_mgr_close(conntrack_mgr_t *m) {
    if (m->fd >= 0) { close(m->fd); m->fd = -1; }
    if (m->del_fd >= 0) { close(m->del_fd); m->del_fd = -1; }
}

static void ct_extract_dst_ip(const uint8_t *data, int len, int family, uint8_t *dst_ip) {
    int offset = 0;
    while (offset + NLA_HDRLEN <= len) {
        uint16_t nla_len, nla_type;
        memcpy(&nla_len, data + offset, 2);
        memcpy(&nla_type, data + offset + 2, 2);
        nla_type &= NLA_TYPE_MASK;
        if (nla_len < NLA_HDRLEN) break;

        if (nla_type == CTA_TUPLE_IP) {
            const uint8_t *inner = data + offset + NLA_HDRLEN;
            int inner_len = nla_len - NLA_HDRLEN;
            int ioff = 0;
            while (ioff + NLA_HDRLEN <= inner_len) {
                uint16_t ilen, itype;
                memcpy(&ilen, inner + ioff, 2);
                memcpy(&itype, inner + ioff + 2, 2);
                itype &= NLA_TYPE_MASK;
                if (ilen < NLA_HDRLEN) break;

                int idata_len = ilen - NLA_HDRLEN;
                const uint8_t *idata = inner + ioff + NLA_HDRLEN;

                if (family == AF_INET && itype == CTA_IPV4_DST && idata_len >= 4) {
                    memcpy(dst_ip, idata, 4);
                    return;
                }
                if (family == AF_INET6 && itype == CTA_IPV6_DST && idata_len >= 16) {
                    memcpy(dst_ip, idata, 16);
                    return;
                }
                ioff += NLA_ALIGN(ilen);
            }
        }
        offset += NLA_ALIGN(nla_len);
    }
}

static int ct_extract_orig_tuple(const uint8_t *data, int len, int family,
                                  const uint8_t **orig_raw, int *orig_len,
                                  uint8_t *dst_ip) {
    int offset = 0;
    while (offset + NLA_HDRLEN <= len) {
        uint16_t nla_len, nla_type;
        memcpy(&nla_len, data + offset, 2);
        memcpy(&nla_type, data + offset + 2, 2);
        nla_type &= NLA_TYPE_MASK;
        if (nla_len < NLA_HDRLEN) break;
        if (offset + NLA_ALIGN(nla_len) > len) break;

        if (nla_type == CTA_TUPLE_ORIG) {
            *orig_raw = data + offset;
            *orig_len = NLA_ALIGN(nla_len);
            ct_extract_dst_ip(data + offset + NLA_HDRLEN, nla_len - NLA_HDRLEN, family, dst_ip);
            return 0;
        }
        offset += NLA_ALIGN(nla_len);
    }
    return -1;
}

static void ct_delete_entry(int fd, int family, const uint8_t *orig_nla, int orig_nla_len) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = CT_MSG_TYPE_DELETE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 2;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = family;

    int offset = NLMSG_HDRLEN + 4;
    if (offset + orig_nla_len > (int)sizeof(buf)) return;
    memcpy(buf + offset, orig_nla, orig_nla_len);
    offset += orig_nla_len;

    nlh->nlmsg_len = offset;
    send(fd, buf, offset, 0);
}

static void ct_drain_del_fd(conntrack_mgr_t *m) {
    uint8_t resp[256];
    int n;
    while ((n = recv(m->del_fd, resp, sizeof(resp), MSG_DONTWAIT)) > 0) {
        struct nlmsghdr *nh = (struct nlmsghdr *)resp;
        if (n >= (int)NLMSG_HDRLEN && nh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
            if (err->error != 0)
                LOG_DEBUG("conntrack delete: errno=%d", -err->error);
        }
    }
}

static int ct_pending_has_family(const conntrack_mgr_t *m, int family) {
    for (int i = 0; i < m->pending_count; i++) {
        if (m->pending[i].family == family) return 1;
    }
    return 0;
}

static void ct_put_attr(uint8_t *buf, int *off, uint16_t type,
                        const void *data, int len) {
    struct nlattr *a = (struct nlattr *)(buf + *off);
    a->nla_type = type;
    a->nla_len = (uint16_t)(NLA_HDRLEN + len);
    memcpy(buf + *off + NLA_HDRLEN, data, len);
    *off += NLA_ALIGN(NLA_HDRLEN + len);
}

static void ct_dump_start(conntrack_mgr_t *m, int family, int heal) {
    uint8_t req[64];
    memset(req, 0, sizeof(req));

    struct nlmsghdr *nlh = (struct nlmsghdr *)req;
    nlh->nlmsg_type = CT_MSG_TYPE_GET;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = 1;

    uint8_t *nfgen = req + NLMSG_HDRLEN;
    nfgen[0] = family;
    int off = NLMSG_HDRLEN + 4;
    uint32_t zero = 0, all = 0xffffffffu;
    ct_put_attr(req, &off, CTA_MARK, &zero, 4);
    ct_put_attr(req, &off, CTA_MARK_MASK, &all, 4);
    nlh->nlmsg_len = off;

    if (send(m->fd, req, nlh->nlmsg_len, 0) < 0) {
        LOG_WARN("conntrack dump send: %s", strerror(errno));
        m->pending_count = 0;
        m->dump_family = 0;
        m->dump_heal = 0;
        m->heal_pending = 0;
        m->rescan = 0;
        m->deleted = 0;
        return;
    }
    m->dump_family = family;
    m->dump_heal = heal;
}

static void ct_next_dump(conntrack_mgr_t *m) {
    m->dump_family = 0;
    m->dump_heal = 0;
    if (m->pending_count) {
        m->rescan = 0;
        ct_dump_start(m, ct_pending_has_family(m, AF_INET) ? AF_INET : AF_INET6, 0);
    } else if (m->heal_pending) {
        m->heal_pending = 0;
        ct_dump_start(m, AF_INET, 1);
    }
}

static void ct_dump_finished(conntrack_mgr_t *m) {
    if (m->deleted > 0)
        LOG_DEBUG("conntrack%s: deleted %d entries", m->dump_heal ? " heal" : "", m->deleted);
    m->deleted = 0;
    if (m->dump_heal) {
        if (m->dump_family == AF_INET) {
            ct_dump_start(m, AF_INET6, 1);
            return;
        }
    } else {
        if (m->dump_family == AF_INET && ct_pending_has_family(m, AF_INET6)) {
            ct_dump_start(m, AF_INET6, 0);
            return;
        }
        if (!m->rescan) m->pending_count = 0;
    }
    ct_next_dump(m);
}

static int ct_pending_match(const conntrack_mgr_t *m, int family, const uint8_t *dst_ip) {
    int ip_len = (family == AF_INET) ? 4 : 16;
    for (int i = 0; i < m->pending_count; i++)
        if (m->pending[i].family == family && memcmp(m->pending[i].ip, dst_ip, ip_len) == 0)
            return 1;
    return 0;
}

void conntrack_process(conntrack_mgr_t *m) {
    if (m->fd < 0) return;

    static uint8_t buf[65536];

    for (int budget = CT_RECV_BUDGET; budget > 0; budget--) {
        int n = recv(m->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n <= 0) return;

        int family = m->dump_family;
        if (family == 0) continue;

        int offset = 0;
        while (offset + (int)NLMSG_HDRLEN <= n) {
            struct nlmsghdr *nh = (struct nlmsghdr *)(buf + offset);
            if (nh->nlmsg_len < NLMSG_HDRLEN || offset + (int)nh->nlmsg_len > n)
                break;

            if (nh->nlmsg_type == NLMSG_DONE || nh->nlmsg_type == NLMSG_ERROR) {
                ct_dump_finished(m);
                break;
            }

            int attr_off = NLMSG_HDRLEN + 4;
            if ((int)nh->nlmsg_len > attr_off) {
                const uint8_t *data = buf + offset + attr_off;
                int data_len = nh->nlmsg_len - attr_off;

                const uint8_t *orig_raw = NULL;
                int orig_len = 0;
                uint8_t dst_ip[16];
                memset(dst_ip, 0, sizeof(dst_ip));

                if (ct_extract_orig_tuple(data, data_len, family,
                                          &orig_raw, &orig_len, dst_ip) == 0 &&
                    (m->dump_heal ? m->heal_match(family, dst_ip)
                                  : ct_pending_match(m, family, dst_ip))) {
                    ct_delete_entry(m->del_fd, family, orig_raw, orig_len);
                    m->deleted++;
                }
            }
            offset += NLMSG_ALIGN(nh->nlmsg_len);
        }

        ct_drain_del_fd(m);
    }
}

void conntrack_flush_request(conntrack_mgr_t *m, const parsed_cidr_t *new_ips, int count) {
    if (!m || m->fd < 0 || count == 0) return;

    int appended = 0;
    for (int i = 0; i < count; i++) {
        int ip_len = (new_ips[i].family == AF_INET) ? 4 : 16;
        int dup = 0;
        for (int j = 0; j < m->pending_count; j++) {
            if (m->pending[j].family == new_ips[i].family &&
                memcmp(m->pending[j].ip, new_ips[i].ip, ip_len) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup) continue;
        if (m->pending_count >= CT_PENDING_MAX) {
            LOG_DEBUG("conntrack: pending buffer full, IP skipped");
            continue;
        }
        m->pending[m->pending_count++] = new_ips[i];
        appended = 1;
    }

    if (!appended) return;
    if (m->dump_family != 0) {
        m->rescan = 1;
        return;
    }
    ct_next_dump(m);
}

void conntrack_heal_request(conntrack_mgr_t *m) {
    if (m->fd < 0 || !m->heal_match) return;
    m->heal_pending = 1;
    if (m->dump_family == 0) ct_next_dump(m);
}

static int ct_nest_begin(uint8_t *buf, int *off, uint16_t type) {
    struct nlattr *a = (struct nlattr *)(buf + *off);
    a->nla_type = (uint16_t)(NLA_F_NESTED | type);
    int handle = *off;
    *off += NLA_HDRLEN;
    return handle;
}

static void ct_nest_end(uint8_t *buf, int off, int handle) {
    struct nlattr *a = (struct nlattr *)(buf + handle);
    a->nla_len = (uint16_t)(off - handle);
}

void conntrack_delete_conn(conntrack_mgr_t *m, const l7_conn_t *c) {
    if (!m || m->del_fd < 0) return;

    int family = (c->family == AF_INET) ? AF_INET : AF_INET6;
    int ip_len = (family == AF_INET) ? 4 : 16;
    uint16_t src_type = (family == AF_INET) ? CTA_IPV4_SRC : CTA_IPV6_SRC;
    uint16_t dst_type = (family == AF_INET) ? CTA_IPV4_DST : CTA_IPV6_DST;

    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = CT_MSG_TYPE_DELETE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 3;

    buf[NLMSG_HDRLEN] = (uint8_t)family;
    int off = NLMSG_HDRLEN + 4;

    int orig = ct_nest_begin(buf, &off, CTA_TUPLE_ORIG);

    int iptup = ct_nest_begin(buf, &off, CTA_TUPLE_IP);
    ct_put_attr(buf, &off, src_type, c->client_ip, ip_len);
    ct_put_attr(buf, &off, dst_type, c->server_ip, ip_len);
    ct_nest_end(buf, off, iptup);

    int proto = ct_nest_begin(buf, &off, CTA_TUPLE_PROTO);
    uint8_t proto_num = c->proto ? c->proto : IPPROTO_TCP;
    uint16_t sport = htons(c->client_port);
    uint16_t dport = htons(c->server_port);
    ct_put_attr(buf, &off, CTA_PROTO_NUM, &proto_num, 1);
    ct_put_attr(buf, &off, CTA_PROTO_SRC_PORT, &sport, 2);
    ct_put_attr(buf, &off, CTA_PROTO_DST_PORT, &dport, 2);
    ct_nest_end(buf, off, proto);

    ct_nest_end(buf, off, orig);

    nlh->nlmsg_len = off;

    send(m->del_fd, buf, off, 0);
    ct_drain_del_fd(m);
}
