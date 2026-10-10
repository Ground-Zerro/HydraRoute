#include "../include/conntrack.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define DUMP_FD 100
#define DEL_FD  101
#define MAX_CT  24

typedef struct {
    uint8_t family;
    uint8_t dst;
    uint32_t mark;
} ct_t;

static ct_t table[MAX_CT];
static int table_len;
static uint8_t reply[8192];
static int reply_len;
static int reply_off;
static int chunked;
static int recvs;
static int dumps;
static uint8_t deleted[32];
static int deleted_count;

static void put_attr(uint8_t *buf, int *off, uint16_t type, const void *data, int len) {
    struct nlattr *a = (struct nlattr *)(buf + *off);
    a->nla_type = type;
    a->nla_len = (uint16_t)(NLA_HDRLEN + len);
    memcpy(buf + *off + NLA_HDRLEN, data, (size_t)len);
    *off += NLA_ALIGN(NLA_HDRLEN + len);
}

static void ip_of(uint8_t family, uint8_t dst, uint8_t *ip) {
    memset(ip, 0, 16);
    if (family == AF_INET) { ip[0] = 198; ip[1] = 51; ip[2] = 100; ip[3] = dst; }
    else { ip[0] = 0x20; ip[1] = 0x01; ip[2] = 0x0d; ip[3] = 0xb8; ip[15] = dst; }
}

static void emit_entry(const ct_t *c) {
    uint8_t *msg = reply + reply_len;
    int off = NLMSG_HDRLEN + 4;
    struct nlattr *orig = (struct nlattr *)(msg + off);
    int orig_at = off;
    off += NLA_HDRLEN;
    struct nlattr *iptup = (struct nlattr *)(msg + off);
    int ip_at = off;
    off += NLA_HDRLEN;
    uint8_t ip[16];
    ip_of(c->family, c->dst, ip);
    put_attr(msg, &off, c->family == AF_INET ? CTA_IPV4_DST : CTA_IPV6_DST, ip,
             c->family == AF_INET ? 4 : 16);
    iptup->nla_type = NLA_F_NESTED | CTA_TUPLE_IP;
    iptup->nla_len = (uint16_t)(off - ip_at);
    orig->nla_type = NLA_F_NESTED | CTA_TUPLE_ORIG;
    orig->nla_len = (uint16_t)(off - orig_at);
    struct nlmsghdr *nh = (struct nlmsghdr *)msg;
    nh->nlmsg_len = (uint32_t)off;
    nh->nlmsg_type = (CT_NFNL_SUBSYS << 8) | 0;
    msg[NLMSG_HDRLEN] = c->family;
    reply_len += NLMSG_ALIGN(off);
}

static int has_attr(const uint8_t *p, int len, uint16_t type, uint32_t *val) {
    while (len >= NLA_HDRLEN) {
        const struct nlattr *a = (const struct nlattr *)p;
        if ((a->nla_type & NLA_TYPE_MASK) == type) {
            memcpy(val, p + NLA_HDRLEN, 4);
            return 1;
        }
        len -= NLA_ALIGN(a->nla_len);
        p += NLA_ALIGN(a->nla_len);
    }
    return 0;
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    const struct nlmsghdr *nh = buf;
    const uint8_t *attrs = (const uint8_t *)buf + NLMSG_HDRLEN + 4;
    int alen = (int)nh->nlmsg_len - NLMSG_HDRLEN - 4;
    uint8_t family = ((const uint8_t *)buf)[NLMSG_HDRLEN];
    if (fd == DEL_FD) {
        const uint8_t *orig = attrs + NLA_HDRLEN;
        const uint8_t *ip = orig + NLA_HDRLEN + NLA_HDRLEN;
        deleted[deleted_count++] = family == AF_INET ? ip[3] : ip[15];
        return (ssize_t)len;
    }
    assert(fd == DUMP_FD && reply_len == 0);
    uint32_t mark, mask;
    assert(has_attr(attrs, alen, CTA_MARK, &mark) && mark == 0);
    assert(has_attr(attrs, alen, CTA_MARK_MASK, &mask) && mask == 0xffffffffu);
    dumps++;
    for (int i = 0; i < table_len; i++)
        if (table[i].family == family && table[i].mark == 0) emit_entry(&table[i]);
    struct nlmsghdr *done = (struct nlmsghdr *)(reply + reply_len);
    done->nlmsg_len = NLMSG_HDRLEN + 4;
    done->nlmsg_type = NLMSG_DONE;
    reply_len += NLMSG_ALIGN(done->nlmsg_len);
    return (ssize_t)len;
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    if (fd == DEL_FD || reply_len == 0) {
        errno = EAGAIN;
        return -1;
    }
    recvs++;
    int n = reply_len - reply_off;
    if (chunked) n = NLMSG_ALIGN(((struct nlmsghdr *)(reply + reply_off))->nlmsg_len);
    memcpy(buf, reply + reply_off, (size_t)n);
    reply_off += n;
    if (reply_off == reply_len) reply_len = reply_off = 0;
    return n;
}

static int heal_match(int family, const uint8_t *dst_ip) {
    uint8_t d = family == AF_INET ? dst_ip[3] : dst_ip[15];
    return d >= 10 && d < 20;
}

static void add_ct(uint8_t family, uint8_t dst, uint32_t mark) {
    table[table_len++] = (ct_t){ family, dst, mark };
}

static void reset(void) {
    dumps = deleted_count = 0;
}

static parsed_cidr_t v4(uint8_t dst) {
    parsed_cidr_t c;
    memset(&c, 0, sizeof(c));
    ip_of(AF_INET, dst, c.ip);
    c.family = AF_INET;
    c.prefix = 32;
    return c;
}

int main(void) {
    conntrack_mgr_t m;
    memset(&m, 0, sizeof(m));
    m.fd = DUMP_FD;
    m.del_fd = DEL_FD;

    add_ct(AF_INET, 11, 0);
    add_ct(AF_INET, 12, 0xffffaab);
    add_ct(AF_INET, 30, 0);
    add_ct(AF_INET, 30, 0xffffaab);
    add_ct(AF_INET, 32, 0xffffaab);
    add_ct(AF_INET6, 13, 0);
    add_ct(AF_INET6, 31, 0);

    conntrack_heal_request(&m);
    assert(m.fd == DUMP_FD);
    reset();
    conntrack_heal_request(&m);
    assert(dumps == 0);
    m.heal_match = heal_match;

    conntrack_heal_request(&m);
    conntrack_process(&m);
    assert(dumps == 2 && m.dump_family == 0);
    assert(deleted_count == 2 && deleted[0] == 11 && deleted[1] == 13);

    reset();
    parsed_cidr_t ip30 = v4(30);
    conntrack_flush_request(&m, &ip30, 1);
    conntrack_heal_request(&m);
    assert(dumps == 1 && m.dump_heal == 0 && m.heal_pending == 1);
    conntrack_process(&m);
    assert(dumps == 3 && m.dump_family == 0 && m.pending_count == 0);
    assert(deleted_count == 3 && deleted[0] == 30 && deleted[1] == 11 && deleted[2] == 13);

    reset();
    parsed_cidr_t ip32 = v4(32);
    conntrack_flush_request(&m, &ip32, 1);
    conntrack_process(&m);
    assert(dumps == 1 && m.dump_family == 0 && m.pending_count == 0 && deleted_count == 0);

    reset();
    conntrack_heal_request(&m);
    conntrack_flush_request(&m, &ip30, 1);
    assert(dumps == 1 && m.dump_heal == 1 && m.pending_count == 1);
    conntrack_process(&m);
    assert(dumps == 3 && m.dump_family == 0 && m.pending_count == 0);
    assert(deleted_count == 3 && deleted[0] == 11 && deleted[1] == 13 && deleted[2] == 30);

    for (uint8_t d = 40; d < 50; d++) add_ct(AF_INET, d, 0);
    chunked = 1;
    reset();
    recvs = 0;
    parsed_cidr_t ip49 = v4(49);
    conntrack_flush_request(&m, &ip49, 1);
    conntrack_process(&m);
    assert(recvs == 8 && m.dump_family == AF_INET && deleted_count == 0);
    conntrack_process(&m);
    assert(recvs == 13 && m.dump_family == 0 && m.pending_count == 0);
    assert(dumps == 1 && deleted_count == 1 && deleted[0] == 49);

    puts("check_conntrack: OK");
    return 0;
}
