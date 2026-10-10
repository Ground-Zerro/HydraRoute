#include "../include/ipset_nl.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define MAX_ELEMS 16
#define MAX_QUEUE 64

typedef struct {
    char     set[32];
    uint8_t  ip[16];
    uint32_t timeout;
    uint32_t expires;
} elem_t;

typedef struct {
    uint32_t seq;
    int      err;
} reply_t;

static elem_t   elems[MAX_ELEMS];
static int      elem_count;
static uint32_t now;
static int      plain_adds;
static int      sends;
static int      drop_replies;
static int      overrun;
static reply_t  queue[MAX_QUEUE];
static int      q_head, q_tail;

int __wrap_clock_gettime(clockid_t id, struct timespec *ts) {
    ts->tv_sec = now;
    ts->tv_nsec = 0;
    return 0;
}

int __wrap___clock_gettime64(clockid_t id, struct timespec *ts) {
    return __wrap_clock_gettime(id, ts);
}

static const uint8_t *attr_find(const uint8_t *p, int len, int type, int *out_len) {
    while (len >= NLA_HDRLEN) {
        uint16_t alen, atype;
        memcpy(&alen, p, 2);
        memcpy(&atype, p + 2, 2);
        if ((atype & NLA_TYPE_MASK) == type) {
            *out_len = alen - NLA_HDRLEN;
            return p + NLA_HDRLEN;
        }
        len -= NLA_ALIGN(alen);
        p += NLA_ALIGN(alen);
    }
    return NULL;
}

static elem_t *elem_find(const char *set, const uint8_t *ip) {
    for (int i = 0; i < elem_count; i++)
        if (strcmp(elems[i].set, set) == 0 && memcmp(elems[i].ip, ip, 16) == 0 &&
            (elems[i].timeout == 0 || now < elems[i].expires))
            return &elems[i];
    return NULL;
}

static void kernel_add(const struct nlmsghdr *nh) {
    const uint8_t *attrs = (const uint8_t *)nh + NLMSG_HDRLEN + 4;
    int alen = (int)nh->nlmsg_len - NLMSG_HDRLEN - 4, n;
    const char *set = (const char *)attr_find(attrs, alen, IPSET_ATTR_SETNAME, &n);
    int dlen, iplen, tlen, alen_ip;
    const uint8_t *data = attr_find(attrs, alen, IPSET_ATTR_DATA, &dlen);
    const uint8_t *ipn = attr_find(data, dlen, IPSET_ATTR_IP, &iplen);
    const uint8_t *addr = attr_find(ipn, iplen, IPSET_ATTR_IPADDR_IPV4, &alen_ip);
    if (!addr) addr = attr_find(ipn, iplen, IPSET_ATTR_IPADDR_IPV6, &alen_ip);
    const uint8_t *t = attr_find(data, dlen, IPSET_ATTR_TIMEOUT, &tlen);
    uint32_t timeout = t ? (uint32_t)t[0] << 24 | (uint32_t)t[1] << 16 | (uint32_t)t[2] << 8 | t[3] : 0;
    uint8_t ip[16] = {0};
    memcpy(ip, addr, (size_t)alen_ip);

    assert(!(nh->nlmsg_flags & NLM_F_ACK));
    elem_t *e = elem_find(set, ip);
    if (e && (nh->nlmsg_flags & NLM_F_EXCL)) {
        assert(q_tail - q_head < MAX_QUEUE);
        queue[q_tail++ % MAX_QUEUE] = (reply_t){ nh->nlmsg_seq, IPSET_ERR_EXIST };
        return;
    }
    if (!(nh->nlmsg_flags & NLM_F_EXCL)) plain_adds++;
    if (!e) {
        assert(elem_count < MAX_ELEMS);
        e = &elems[elem_count++];
        snprintf(e->set, sizeof(e->set), "%s", set);
        memcpy(e->ip, ip, 16);
    }
    e->timeout = timeout;
    e->expires = now + timeout;
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    sends++;
    for (size_t off = 0; off < len; ) {
        const struct nlmsghdr *nh = (const struct nlmsghdr *)((const uint8_t *)buf + off);
        kernel_add(nh);
        off += NLMSG_ALIGN(nh->nlmsg_len);
    }
    if (drop_replies) {
        drop_replies = 0;
        overrun = 1;
        q_head = q_tail;
    }
    return (ssize_t)len;
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    assert(flags & MSG_DONTWAIT);
    if (overrun) {
        overrun = 0;
        errno = ENOBUFS;
        return -1;
    }
    if (q_head == q_tail) {
        errno = EAGAIN;
        return -1;
    }
    reply_t rp = queue[q_head++ % MAX_QUEUE];
    struct nlmsghdr *nh = buf;
    struct nlmsgerr *e = (struct nlmsgerr *)((uint8_t *)buf + NLMSG_HDRLEN);
    nh->nlmsg_type = NLMSG_ERROR;
    nh->nlmsg_len = NLMSG_HDRLEN + sizeof(*e);
    nh->nlmsg_seq = rp.seq;
    e->error = -rp.err;
    return (ssize_t)nh->nlmsg_len;
}

static parsed_cidr_t v4(uint8_t last) {
    parsed_cidr_t c;
    memset(&c, 0, sizeof(c));
    c.ip[0] = 203; c.ip[1] = 0; c.ip[2] = 113; c.ip[3] = last;
    c.prefix = 32;
    c.family = AF_INET;
    return c;
}

static const elem_t *elem(const char *set, uint8_t last) {
    parsed_cidr_t c = v4(last);
    return elem_find(set, c.ip);
}

static int dns_add(ipset_manager_t *m, const char *set, int owner, uint8_t last) {
    parsed_cidr_t c = v4(last);
    int new_count = -1, idx[1];
    assert(ipset_add_batch(m, set, &c, 1, owner, &new_count, idx) == 0);
    return new_count;
}

int main(void) {
    ipset_manager_t m;
    memset(&m, 0, sizeof(m));
    m.default_timeout = 100;

    parsed_cidr_t perm = v4(1);
    assert(ipset_add_batch(&m, "HR", &perm, 1, IPSET_PERMANENT, NULL, NULL) == 0);
    assert(elem("HR", 1)->timeout == 0);

    now = 1000;
    assert(dns_add(&m, "HR", 0, 1) == 0);
    now = 1080;
    assert(dns_add(&m, "HR", 0, 1) == 0);
    assert(plain_adds == 1 && elem("HR", 1)->timeout == 0);

    now = 2000;
    assert(dns_add(&m, "HR", 0, 2) == 1);
    assert(elem("HR", 2)->expires == 2100);
    now = 2040;
    int sent = sends;
    assert(dns_add(&m, "HR", 0, 2) == 0);
    assert(sends == sent && plain_adds == 1 && elem("HR", 2)->expires == 2100);
    now = 2050;
    assert(dns_add(&m, "HR", 0, 2) == 0);
    assert(plain_adds == 2 && elem("HR", 2)->expires == 2150);
    now = 2060;
    assert(dns_add(&m, "HR", 0, 2) == 0);
    assert(plain_adds == 2 && elem("HR", 2)->expires == 2150);

    assert(dns_add(&m, "RU", 1, 2) == 1);
    now = 2140;
    assert(dns_add(&m, "RU", 1, 2) == 0);
    assert(plain_adds == 3 && elem("RU", 2)->expires == 2240 && elem("HR", 2)->expires == 2150);

    now = 2200;
    assert(!elem("HR", 2));
    assert(dns_add(&m, "HR", 0, 2) == 1);
    assert(elem("HR", 2)->expires == 2300);

    m.default_timeout = 0;
    now = 3000;
    assert(dns_add(&m, "NT", 0, 3) == 1);
    now = 9000;
    assert(dns_add(&m, "NT", 0, 3) == 0);
    assert(plain_adds == 3 && elem("NT", 3)->timeout == 0);

    m.default_timeout = 100;
    now = 4000;
    parsed_cidr_t batch[3] = { v4(1), v4(4), v4(5) };
    int nc = -1, ni[3];
    sent = sends;
    queue[q_tail++ % MAX_QUEUE] = (reply_t){ m.seq - 1, ENOENT };
    queue[q_tail++ % MAX_QUEUE] = (reply_t){ m.seq - 7, IPSET_ERR_EXIST };
    assert(ipset_add_batch(&m, "HR", batch, 3, 0, &nc, ni) == 0);
    assert(sends == sent + 1 && q_head == q_tail);
    assert(nc == 2 && ni[0] == 1 && ni[1] == 2);

    drop_replies = 1;
    assert(dns_add(&m, "HR", 0, 6) == 0);
    assert(elem("HR", 6)->expires == 4100);
    now = 4060;
    int plain = plain_adds;
    assert(dns_add(&m, "HR", 0, 6) == 0);
    assert(plain_adds == plain && elem("HR", 6)->expires == 4100);

    assert(q_head == q_tail);
    puts("check_ipset: OK");
    return 0;
}
