#include "../include/ipset_nl.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

#define IPSET_ADT_MSG_MAX 160
#define IPSET_REPLY_MAX   512

static void ipset_add_to_cache(ipset_manager_t *mgr, const char *name);

static void put_u32_network(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >>  8) & 0xFF;
    buf[3] =  val        & 0xFF;
}

static int nla_put_u8(uint8_t *buf, uint16_t type, uint8_t val) {
    uint16_t nla_len = NLA_HDRLEN + 1;
    memcpy(buf, &nla_len, 2);
    memcpy(buf + 2, &type, 2);
    buf[NLA_HDRLEN] = val;
    return NLA_ALIGN(nla_len);
}

static int nla_put_string(uint8_t *buf, uint16_t type, const char *str) {
    int slen = strlen(str) + 1;
    uint16_t nla_len = NLA_HDRLEN + slen;
    memcpy(buf, &nla_len, 2);
    memcpy(buf + 2, &type, 2);
    memcpy(buf + NLA_HDRLEN, str, slen);
    return NLA_ALIGN(nla_len);
}

static int nla_put_raw(uint8_t *buf, uint16_t type, const uint8_t *data, int data_len) {
    uint16_t nla_len = NLA_HDRLEN + data_len;
    memcpy(buf, &nla_len, 2);
    memcpy(buf + 2, &type, 2);
    memcpy(buf + NLA_HDRLEN, data, data_len);
    return NLA_ALIGN(nla_len);
}

static int nl_exchange(ipset_manager_t *mgr, const uint8_t *buf, int len, int n, int *errs, uint8_t *reply) {
    uint32_t seq0 = ((const struct nlmsghdr *)buf)->nlmsg_seq;
    for (int i = 0; i < n; i++) errs[i] = 0;
    if (send(mgr->fd, buf, len, 0) < 0) {
        LOG_ERROR("netlink send: %s", strerror(errno));
        return -1;
    }

    uint8_t resp[IPSET_REPLY_MAX];
    int reply_len = 0, lost = 0;
    for (;;) {
        ssize_t r = recv(mgr->fd, resp, sizeof(resp), MSG_DONTWAIT);
        if (r < 0) {
            if (errno != ENOBUFS) break;
            lost = 1;
            continue;
        }
        const struct nlmsghdr *nh = (const struct nlmsghdr *)resp;
        uint32_t k = nh->nlmsg_seq - seq0;
        if (r < (ssize_t)(NLMSG_HDRLEN + sizeof(struct nlmsgerr)) || k >= (uint32_t)n) continue;
        if (nh->nlmsg_type == NLMSG_ERROR) {
            errs[k] = -((const struct nlmsgerr *)NLMSG_DATA(nh))->error;
        } else if (reply) {
            memcpy(reply, resp, (size_t)r);
            reply_len = (int)r;
        }
    }

    if (lost) {
        LOG_WARN("netlink: ipset replies lost (ENOBUFS)");
        for (int i = 0; i < n; i++)
            if (errs[i] == 0) errs[i] = -1;
    }
    return reply_len;
}

static int nl_request(ipset_manager_t *mgr, const uint8_t *buf, int len) {
    int err;
    return nl_exchange(mgr, buf, len, 1, &err, NULL) < 0 ? -1 : err;
}

int ipset_manager_init(ipset_manager_t *mgr) {
    memset(mgr, 0, sizeof(*mgr));
    mgr->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (mgr->fd < 0) {
        LOG_ERROR("netlink socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;

    if (bind(mgr->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG_ERROR("netlink bind: %s", strerror(errno));
        close(mgr->fd);
        mgr->fd = -1;
        return -1;
    }

    mgr->seq = 1;
    mgr->pid = getpid();
    return 0;
}

void ipset_manager_close(ipset_manager_t *mgr) {
    if (mgr->fd >= 0) close(mgr->fd);
    mgr->fd = -1;
}

static int ipset_query_revision(ipset_manager_t *mgr, const char *type, int family) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TYPE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = mgr->seq++;
    nlh->nlmsg_pid = mgr->pid;

    uint8_t nf_family = (family == AF_INET6) ? 10 : 2;
    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = nf_family;

    int offset = NLMSG_HDRLEN + 4;
    offset += nla_put_u8(buf + offset, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    offset += nla_put_string(buf + offset, IPSET_ATTR_TYPENAME, type);
    offset += nla_put_u8(buf + offset, IPSET_ATTR_FAMILY, nf_family);
    nlh->nlmsg_len = offset;

    uint8_t resp[IPSET_REPLY_MAX];
    int err;
    int n = nl_exchange(mgr, buf, offset, 1, &err, resp);
    if (n < (int)(NLMSG_HDRLEN + 4))
        return 0;

    uint8_t *attrs = resp + NLMSG_HDRLEN + 4;
    int attrs_len = n - NLMSG_HDRLEN - 4;
    int pos = 0;
    while (pos + NLA_HDRLEN <= attrs_len) {
        uint16_t nla_len, nla_type;
        memcpy(&nla_len, attrs + pos, 2);
        memcpy(&nla_type, attrs + pos + 2, 2);
        if ((nla_type & ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)) == IPSET_ATTR_REVISION
                && nla_len >= (uint16_t)(NLA_HDRLEN + 1))
            return attrs[pos + NLA_HDRLEN];
        int next = NLA_ALIGN(nla_len);
        if (next <= 0 || pos + next > attrs_len)
            break;
        pos += next;
    }
    return 0;
}

static int build_create_msg(uint8_t *buf, int buf_size, ipset_manager_t *mgr,
                            const char *name, const char *type, int family,
                            uint32_t timeout, uint32_t maxelem, uint8_t revision) {
    memset(buf, 0, buf_size);

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_CREATE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = mgr->seq++;
    nlh->nlmsg_pid = mgr->pid;

    uint8_t nf_family = (family == AF_INET6) ? 10 : 2;
    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = nf_family;

    int offset = NLMSG_HDRLEN + 4;
    offset += nla_put_u8(buf + offset, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    offset += nla_put_string(buf + offset, IPSET_ATTR_SETNAME, name);
    offset += nla_put_string(buf + offset, IPSET_ATTR_TYPENAME, type);
    offset += nla_put_u8(buf + offset, IPSET_ATTR_REVISION, revision);
    offset += nla_put_u8(buf + offset, IPSET_ATTR_FAMILY, nf_family);

    if (timeout > 0 || maxelem > 0) {
        uint8_t data_buf[32];
        int data_len = 0;
        if (timeout > 0) {
            uint8_t timeout_bytes[4];
            put_u32_network(timeout_bytes, timeout);
            data_len += nla_put_raw(data_buf + data_len,
                                    IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER,
                                    timeout_bytes, 4);
        }
        if (maxelem > 0) {
            uint8_t maxelem_bytes[4];
            put_u32_network(maxelem_bytes, maxelem);
            data_len += nla_put_raw(data_buf + data_len,
                                    IPSET_ATTR_MAXELEM | NLA_F_NET_BYTEORDER,
                                    maxelem_bytes, 4);
        }
        offset += nla_put_raw(buf + offset, IPSET_ATTR_DATA | NLA_F_NESTED,
                                 data_buf, data_len);
    }

    nlh->nlmsg_len = offset;
    return offset;
}


int ipset_create(ipset_manager_t *mgr, const char *name, const char *type, int family, uint32_t timeout, uint32_t maxelem) {
    uint8_t revision = (uint8_t)ipset_query_revision(mgr, type, family);

    LOG_DEBUG("Netlink CREATE: set=%s type=%s family=%d timeout=%u revision=%u",
              name, type, family, timeout, revision);

    uint8_t buf[512];
    int msg_len = build_create_msg(buf, sizeof(buf), mgr, name, type, family,
                                   timeout, maxelem, revision);
    int ret = nl_request(mgr, buf, msg_len);

    if (ret == 17) {
        LOG_DEBUG("Set %s already exists", name);
        ipset_add_to_cache(mgr, name);
        return 0;
    }
    if (ret != 0) {
        LOG_ERROR("Netlink CREATE error for %s: errno=%d", name, ret);
        return ret;
    }

    LOG_DEBUG("Set %s created", name);
    ipset_add_to_cache(mgr, name);
    return 0;
}

int ipset_flush(ipset_manager_t *mgr, const char *name) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_FLUSH;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = mgr->seq++;
    nlh->nlmsg_pid = mgr->pid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = 2;

    int offset = NLMSG_HDRLEN + 4;
    offset += nla_put_u8(buf + offset, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    offset += nla_put_string(buf + offset, IPSET_ATTR_SETNAME, name);

    nlh->nlmsg_len = offset;

    LOG_DEBUG("Netlink FLUSH: set=%s", name);

    int ret = nl_request(mgr, buf, offset);
    if (ret != 0) {
        LOG_DEBUG("Netlink FLUSH error: errno=%d", ret);
        return ret;
    }

    LOG_DEBUG("Netlink success: set %s flushed", name);
    return 0;
}

static int build_ipset_adt_msg(uint8_t *buf, int buf_size, ipset_manager_t *mgr,
                               uint8_t cmd, uint16_t flags,
                               const char *set_name_nul, int set_name_len,
                               const parsed_cidr_t *entry,
                               int has_timeout, const uint8_t *timeout_bytes) {
    memset(buf, 0, buf_size > 256 ? 256 : buf_size);

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | cmd;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = mgr->seq++;
    nlh->nlmsg_pid = mgr->pid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = 2;

    int offset = NLMSG_HDRLEN + 4;
    offset += nla_put_u8(buf + offset, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);

    {
        uint16_t nla_len_val = NLA_HDRLEN + set_name_len;
        uint16_t nla_type_val = IPSET_ATTR_SETNAME;
        memcpy(buf + offset, &nla_len_val, 2);
        memcpy(buf + offset + 2, &nla_type_val, 2);
        memcpy(buf + offset + NLA_HDRLEN, set_name_nul, set_name_len);
        offset += NLA_ALIGN(nla_len_val);
    }

    uint8_t data_buf[64];
    int data_len = 0;

    {
        uint8_t ip_buf[32];
        int ip_len = 0;
        if (entry->family == AF_INET) {
            uint16_t attr_type = IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER;
            uint16_t attr_len = NLA_HDRLEN + 4;
            memcpy(ip_buf + ip_len, &attr_len, 2);
            memcpy(ip_buf + ip_len + 2, &attr_type, 2);
            memcpy(ip_buf + ip_len + NLA_HDRLEN, entry->ip, 4);
            ip_len += NLA_ALIGN(attr_len);
        } else {
            uint16_t attr_type = IPSET_ATTR_IPADDR_IPV6 | NLA_F_NET_BYTEORDER;
            uint16_t attr_len = NLA_HDRLEN + 16;
            memcpy(ip_buf + ip_len, &attr_len, 2);
            memcpy(ip_buf + ip_len + 2, &attr_type, 2);
            memcpy(ip_buf + ip_len + NLA_HDRLEN, entry->ip, 16);
            ip_len += NLA_ALIGN(attr_len);
        }

        data_len += nla_put_raw(data_buf + data_len, IPSET_ATTR_IP | NLA_F_NESTED,
                                   ip_buf, ip_len);
    }

    data_len += nla_put_u8(data_buf + data_len, IPSET_ATTR_CIDR, entry->prefix);

    if (has_timeout) {
        data_len += nla_put_raw(data_buf + data_len,
                                IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER,
                                timeout_bytes, 4);
    }

    offset += nla_put_raw(buf + offset, IPSET_ATTR_DATA | NLA_F_NESTED,
                             data_buf, data_len);

    nlh->nlmsg_len = offset;
    return offset;
}

static int is_service_ip(const uint8_t *ip, int family) {
    if (family == AF_INET) {
        return (ip[0] == 0 || ip[0] == 127);
    }
    static const uint8_t zeros[16] = {0};
    static const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return (memcmp(ip, zeros, 16) == 0 || memcmp(ip, loopback, 16) == 0);
}

typedef struct {
    uint8_t  ip[16];
    uint32_t refresh_at;
    int16_t  owner;
    uint8_t  family;
} owned_slot_t;

static owned_slot_t g_owned[IPSET_OWNED_SLOTS];

static uint32_t now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)ts.tv_sec;
}

static owned_slot_t *owned_slot(int owner, const parsed_cidr_t *e) {
    uint32_t h = fnv1a_hash((const char *)e->ip, sizeof(e->ip)) ^ ((uint32_t)owner * 0x9e3779b9u);
    return &g_owned[h & (IPSET_OWNED_SLOTS - 1)];
}

static int owned_by(const owned_slot_t *s, int owner, const parsed_cidr_t *e) {
    return s->family == e->family && s->owner == owner && memcmp(s->ip, e->ip, sizeof(s->ip)) == 0;
}

static int send_adds(ipset_manager_t *mgr, const char *set_name_nul, int set_name_len,
                     const parsed_cidr_t *entries, const int *idx, int n,
                     int has_timeout, const uint8_t *timeout_bytes, uint16_t flags, int *errs) {
    static uint8_t batch[IPSET_CHUNK_SIZE * IPSET_ADT_MSG_MAX];
    int len = 0;
    for (int i = 0; i < n; i++)
        len += build_ipset_adt_msg(batch + len, (int)sizeof(batch) - len, mgr,
                                   IPSET_CMD_ADD, NLM_F_CREATE | flags,
                                   set_name_nul, set_name_len, &entries[idx[i]],
                                   has_timeout, timeout_bytes);
    return nl_exchange(mgr, batch, len, n, errs, NULL) < 0 ? -1 : 0;
}

int ipset_add_batch(ipset_manager_t *mgr, const char *set_name,
                    const parsed_cidr_t *entries, int count,
                    int owner, int *new_count, int *new_indices) {
    if (new_count) *new_count = 0;
    if (count == 0) return 0;

    int has_timeout = mgr->default_timeout > 0;
    int dynamic = owner != IPSET_PERMANENT;
    int tracked = dynamic && has_timeout;
    uint32_t now = now_sec();
    uint32_t refresh_at = now + mgr->default_timeout / 2;

    uint8_t timeout_bytes[4] = {0};
    if (has_timeout && dynamic) put_u32_network(timeout_bytes, mgr->default_timeout);

    char set_name_nul[64];
    int set_name_len = snprintf(set_name_nul, sizeof(set_name_nul), "%s", set_name) + 1;

    for (int start = 0; start < count; start += IPSET_CHUNK_SIZE) {
        int end = start + IPSET_CHUNK_SIZE;
        if (end > count) end = count;

        int idx[IPSET_CHUNK_SIZE], errs[IPSET_CHUNK_SIZE], ext[IPSET_CHUNK_SIZE];
        int n = 0, ne = 0;
        for (int i = start; i < end; i++) {
            if (is_service_ip(entries[i].ip, entries[i].family)) {
                LOG_FILTERED("Service IP rejected (family=%d)", entries[i].family);
                continue;
            }
            if (tracked) {
                const owned_slot_t *slot = owned_slot(owner, &entries[i]);
                if (owned_by(slot, owner, &entries[i]) && (int32_t)(now - slot->refresh_at) < 0)
                    continue;
            }
            idx[n++] = i;
        }
        if (n == 0) continue;

        if (send_adds(mgr, set_name_nul, set_name_len, entries, idx, n, has_timeout,
                      timeout_bytes, dynamic ? NLM_F_EXCL : 0, errs) != 0)
            return -1;

        for (int i = 0; i < n; i++) {
            const parsed_cidr_t *e = &entries[idx[i]];
            if (errs[i] == 0) {
                if (dynamic && new_indices) new_indices[(*new_count)++] = idx[i];
                if (tracked) {
                    owned_slot_t *slot = owned_slot(owner, e);
                    memcpy(slot->ip, e->ip, sizeof(slot->ip));
                    slot->family = e->family;
                    slot->owner = (int16_t)owner;
                    slot->refresh_at = refresh_at;
                }
            } else if (errs[i] == IPSET_ERR_EXIST) {
                if (tracked && owned_by(owned_slot(owner, e), owner, e))
                    ext[ne++] = idx[i];
            } else if (errs[i] == IPSET_ERR_HASH_FULL) {
                LOG_WARN("ipset '%s' full (maxelem exceeded): set IpsetMaxElem in config", set_name);
            } else if (errs[i] > 0) {
                LOG_DEBUG("Netlink ADD error: errno=%d", errs[i]);
            }
        }

        if (ne == 0) continue;
        if (send_adds(mgr, set_name_nul, set_name_len, entries, ext, ne, has_timeout,
                      timeout_bytes, 0, errs) != 0)
            return -1;
        for (int i = 0; i < ne; i++)
            if (errs[i] == 0) owned_slot(owner, &entries[ext[i]])->refresh_at = refresh_at;
        LOG_DEBUG("ipset %s: timeout extended for %d owned entries", set_name, ne);
    }

    return 0;
}

int ipset_test(ipset_manager_t *mgr, const char *set_name, const parsed_cidr_t *entry) {
    uint8_t buf[256];
    char set_name_nul[64];
    int set_name_len = snprintf(set_name_nul, sizeof(set_name_nul), "%s", set_name) + 1;
    int len = build_ipset_adt_msg(buf, sizeof(buf), mgr, IPSET_CMD_TEST, 0,
                                  set_name_nul, set_name_len, entry, 0, NULL);
    return nl_request(mgr, buf, len) == 0;
}

int ipset_refresh_set_list(ipset_manager_t *mgr) {
    char output[32768];
    char *argv[] = {"ipset", "list", "-n", NULL};
    int ret = run_command_output("ipset", argv, output, sizeof(output));
    if (ret != 0) {
        LOG_WARN("ipset list -n failed (exit %d)", ret);
        return -1;
    }

    mgr->set_count = 0;
    char *saveptr;
    char *line = strtok_r(output, "\n", &saveptr);
    while (line && mgr->set_count < IPSET_MAX_SETS) {
        char *trimmed = trim_whitespace(line);
        if (trimmed[0] != '\0') {
            strncpy(mgr->set_names[mgr->set_count], trimmed, 63);
            mgr->set_names[mgr->set_count][63] = '\0';
            mgr->set_count++;
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }

    LOG_DEBUG("RefreshSetList: loaded %d sets into cache", mgr->set_count);
    return 0;
}

int ipset_set_exists(ipset_manager_t *mgr, const char *name) {
    for (int i = 0; i < mgr->set_count; i++) {
        if (strcmp(mgr->set_names[i], name) == 0) return 1;
    }
    return 0;
}

static void ipset_add_to_cache(ipset_manager_t *mgr, const char *name) {
    if (mgr->set_count < IPSET_MAX_SETS) {
        strncpy(mgr->set_names[mgr->set_count], name, 63);
        mgr->set_names[mgr->set_count][63] = '\0';
        mgr->set_count++;
        LOG_DEBUG("AddToCache: added %s to cache", name);
    }
}
