#include "../include/conntrack.h"
#include "../include/log.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <netinet/in.h>

#define CT_MSG_TYPE_GET    ((CT_NFNL_SUBSYS << 8) | CT_MSG_GET)
#define CT_MSG_TYPE_DELETE ((CT_NFNL_SUBSYS << 8) | CT_MSG_DELETE)

int conntrack_mgr_init(conntrack_mgr_t *m) {
    m->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (m->fd < 0) {
        LOG_ERROR("conntrack socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    bind(m->fd, (struct sockaddr *)&sa, sizeof(sa));
    return 0;
}

void conntrack_mgr_close(conntrack_mgr_t *m) {
    if (m->fd >= 0) { close(m->fd); m->fd = -1; }
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

static int ct_delete_entry(int fd, int family, const uint8_t *orig_nla, int orig_nla_len) {
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = CT_MSG_TYPE_DELETE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = 2;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = family;

    int offset = NLMSG_HDRLEN + 4;
    if (offset + orig_nla_len > (int)sizeof(buf)) return 0;
    memcpy(buf + offset, orig_nla, orig_nla_len);
    offset += orig_nla_len;

    nlh->nlmsg_len = offset;

    if (send(fd, buf, offset, 0) < 0) return 0;

    uint8_t resp[256];
    int n = recv(fd, resp, sizeof(resp), 0);
    if (n <= 0) return 0;

    struct nlmsghdr *rnh = (struct nlmsghdr *)resp;
    if (rnh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(rnh);
        return (err->error == 0) ? 1 : 0;
    }
    return 0;
}

static void ct_flush_family(int fd, int family,
                            const uint8_t (*targets)[16], int target_count,
                            int ip_len) {
    uint8_t req[64];
    memset(req, 0, sizeof(req));

    struct nlmsghdr *nlh = (struct nlmsghdr *)req;
    nlh->nlmsg_type = CT_MSG_TYPE_GET;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_len = NLMSG_HDRLEN + 4;
    nlh->nlmsg_seq = 1;

    uint8_t *nfgen = req + NLMSG_HDRLEN;
    nfgen[0] = family;

    if (send(fd, req, nlh->nlmsg_len, 0) < 0) {
        LOG_WARN("conntrack dump send: %s", strerror(errno));
        return;
    }

    static uint8_t buf[65536];
    int deleted = 0;
    int done = 0;

    while (!done) {
        int n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;

        int offset = 0;
        while (offset + (int)NLMSG_HDRLEN <= n) {
            struct nlmsghdr *nh = (struct nlmsghdr *)(buf + offset);
            if (nh->nlmsg_len < NLMSG_HDRLEN || offset + (int)nh->nlmsg_len > n)
                break;

            if (nh->nlmsg_type == NLMSG_DONE) { done = 1; break; }
            if (nh->nlmsg_type == NLMSG_ERROR) { done = 1; break; }

            int attr_off = NLMSG_HDRLEN + 4;
            if ((int)nh->nlmsg_len > attr_off) {
                const uint8_t *data = buf + offset + attr_off;
                int data_len = nh->nlmsg_len - attr_off;

                const uint8_t *orig_raw = NULL;
                int orig_len = 0;
                uint8_t dst_ip[16];
                memset(dst_ip, 0, sizeof(dst_ip));

                if (ct_extract_orig_tuple(data, data_len, family,
                                          &orig_raw, &orig_len, dst_ip) == 0) {
                    for (int i = 0; i < target_count; i++) {
                        if (memcmp(targets[i], dst_ip, ip_len) == 0) {
                            if (ct_delete_entry(fd, family, orig_raw, orig_len))
                                deleted++;
                            break;
                        }
                    }
                }
            }
            offset += NLMSG_ALIGN(nh->nlmsg_len);
        }
    }

    if (deleted > 0)
        LOG_DEBUG("conntrack: deleted %d entries (family %d)", deleted, family);
}

void conntrack_flush_for_ips(conntrack_mgr_t *m, const parsed_cidr_t *new_ips, int count) {
    if (!m || m->fd < 0 || count == 0) return;

    uint8_t ipv4_set[64][16];
    int ipv4_count = 0;
    uint8_t ipv6_set[64][16];
    int ipv6_count = 0;

    for (int i = 0; i < count && i < 64; i++) {
        if (new_ips[i].family == AF_INET) {
            memset(ipv4_set[ipv4_count], 0, 16);
            memcpy(ipv4_set[ipv4_count], new_ips[i].ip, 4);
            ipv4_count++;
        } else {
            memcpy(ipv6_set[ipv6_count], new_ips[i].ip, 16);
            ipv6_count++;
        }
    }

    if (ipv4_count == 0 && ipv6_count == 0) return;

    if (ipv4_count > 0)
        ct_flush_family(m->fd, AF_INET, (const uint8_t (*)[16])ipv4_set, ipv4_count, 4);
    if (ipv6_count > 0)
        ct_flush_family(m->fd, AF_INET6, (const uint8_t (*)[16])ipv6_set, ipv6_count, 16);
}
