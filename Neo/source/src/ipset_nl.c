#include "../include/ipset_nl.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

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

static int nl_send_recv_ack(ipset_manager_t *mgr, uint8_t *buf, int len) {
    if (send(mgr->fd, buf, len, 0) < 0) {
        LOG_ERROR("netlink send: %s", strerror(errno));
        return -1;
    }

    uint8_t resp[512];
    int n = recv(mgr->fd, resp, sizeof(resp), 0);
    if (n < 0) {
        LOG_ERROR("netlink recv: %s", strerror(errno));
        return -1;
    }

    struct nlmsghdr *nh = (struct nlmsghdr *)resp;
    if (nh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)((uint8_t *)nh + NLMSG_HDRLEN);
        if (err->error != 0) {
            return -err->error;
        }
    }
    return 0;
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

    if (send(mgr->fd, buf, offset, 0) < 0)
        return 0;

    uint8_t resp[512];
    int n = recv(mgr->fd, resp, sizeof(resp), 0);
    if (n < (int)(NLMSG_HDRLEN + 4))
        return 0;

    struct nlmsghdr *rnh = (struct nlmsghdr *)resp;
    if (rnh->nlmsg_type == NLMSG_ERROR)
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
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
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
    int ret = nl_send_recv_ack(mgr, buf, msg_len);

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
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = mgr->seq++;
    nlh->nlmsg_pid = mgr->pid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = 2;

    int offset = NLMSG_HDRLEN + 4;
    offset += nla_put_u8(buf + offset, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    offset += nla_put_string(buf + offset, IPSET_ATTR_SETNAME, name);

    nlh->nlmsg_len = offset;

    LOG_DEBUG("Netlink FLUSH: set=%s", name);

    int ret = nl_send_recv_ack(mgr, buf, offset);
    if (ret != 0) {
        LOG_DEBUG("Netlink FLUSH error: errno=%d", ret);
        return ret;
    }

    LOG_DEBUG("Netlink success: set %s flushed", name);
    return 0;
}

static int build_ipset_add_msg(uint8_t *buf, int buf_size, ipset_manager_t *mgr,
                               const char *set_name_nul, int set_name_len,
                               const parsed_cidr_t *entry,
                               int has_timeout, const uint8_t *timeout_bytes,
                               uint16_t extra_flags) {
    memset(buf, 0, buf_size > 256 ? 256 : buf_size);

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_ADD;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | extra_flags;
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

int ipset_add_batch(ipset_manager_t *mgr, const char *set_name,
                    const parsed_cidr_t *entries, int count,
                    int with_timeout, int *new_count, int *new_indices) {
    if (count == 0) return 0;

    uint32_t idx = fnv1a_hash(set_name, strlen(set_name)) & 0xFF;
    int has_timeout = mgr->set_has_timeout[idx];
    uint32_t timeout_val = mgr->timeout_value[idx];

    uint8_t timeout_bytes[4] = {0};
    if (has_timeout && with_timeout) {
        put_u32_network(timeout_bytes, timeout_val);
    }

    uint16_t excl_flag = with_timeout ? NLM_F_EXCL : 0;

    char set_name_nul[64];
    int set_name_len = snprintf(set_name_nul, sizeof(set_name_nul), "%s", set_name) + 1;

    *new_count = 0;

    for (int start = 0; start < count; start += IPSET_CHUNK_SIZE) {
        int end = start + IPSET_CHUNK_SIZE;
        if (end > count) end = count;

        uint8_t msg_bufs[IPSET_CHUNK_SIZE][256];
        int msg_lens[IPSET_CHUNK_SIZE];
        int valid_indices[IPSET_CHUNK_SIZE];
        int msg_count = 0;

        for (int i = start; i < end; i++) {
            if (is_service_ip(entries[i].ip, entries[i].family)) {
                LOG_FILTERED("Service IP rejected (family=%d)", entries[i].family);
                continue;
            }

            msg_lens[msg_count] = build_ipset_add_msg(
                msg_bufs[msg_count], sizeof(msg_bufs[msg_count]),
                mgr, set_name_nul, set_name_len,
                &entries[i],
                has_timeout, timeout_bytes,
                excl_flag);
            valid_indices[msg_count] = i;
            msg_count++;
        }

        if (msg_count == 0) continue;

        for (int i = 0; i < msg_count; i++) {
            if (send(mgr->fd, msg_bufs[i], msg_lens[i], 0) < 0) {
                LOG_ERROR("netlink send batch: %s", strerror(errno));
                return -1;
            }
        }

        for (int i = 0; i < msg_count; i++) {
            uint8_t resp[256];
            int n = recv(mgr->fd, resp, sizeof(resp), 0);
            if (n < 0) continue;

            struct nlmsghdr *nh = (struct nlmsghdr *)resp;
            if (nh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)((uint8_t *)nh + NLMSG_HDRLEN);
                if (err->error == 0) {
                    if (with_timeout && new_indices) {
                        new_indices[*new_count] = valid_indices[i];
                        (*new_count)++;
                    }
                } else {
                    int errcode = -err->error;
                    if (errcode == IPSET_ERR_HASH_FULL) {
                        LOG_WARN("ipset '%s' full (maxelem exceeded): set IpsetMaxElem in config", set_name);
                    } else if (errcode != IPSET_ERR_EXIST) {
                        LOG_DEBUG("Netlink ADD error: errno=%d", errcode);
                    }
                }
            }
        }
    }

    return 0;
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

void ipset_cache_timeout_for_set(ipset_manager_t *mgr, const char *name,
                                 int has_timeout, uint32_t timeout_val) {
    uint32_t idx = fnv1a_hash(name, strlen(name)) & 0xFF;
    mgr->set_has_timeout[idx] = has_timeout;
    mgr->timeout_value[idx] = timeout_val;
}
