#define _GNU_SOURCE
#include "../include/watchlist_api.h"
#include "../include/watchlist.h"
#include "../include/util.h"
#include "../include/log.h"
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define WLAPI_MAX_CLIENTS 4
#define WLAPI_IN_BUF      512
#define WLAPI_OUT_BUF     8192
#define WLAPI_LINE_MAX    384
#define WLAPI_NAME_MAX    253

typedef struct {
    int fd;
    uint32_t events;
    int eof;
    int dumping;
    int dump_rank;
    unsigned dump_bucket;
    unsigned dumped;
    const domain_node_t *dump_node;
    size_t in_len;
    size_t out_off;
    size_t out_len;
    char in[WLAPI_IN_BUF];
    char out[WLAPI_OUT_BUF];
} wlapi_client_t;

static struct {
    const domain_hashtable_t *ht;
    int listen_fd;
    int stop_fd;
    int epfd;
    int running;
    pthread_t thread;
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
} g_api = { .listen_fd = -1, .stop_fd = -1, .epfd = -1 };

static wlapi_client_t g_clients[WLAPI_MAX_CLIENTS];

__attribute__((format(printf, 2, 3)))
static int out_fmt(wlapi_client_t *c, const char *fmt, ...) {
    size_t room = WLAPI_OUT_BUF - c->out_len;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(c->out + c->out_len, room, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= room) return -1;
    c->out_len += (size_t)n;
    return 0;
}

static const ht_target_t *target_by_rank(int rank) {
    for (int i = 0; i < g_api.ht->target_count; i++) {
        if (g_api.ht->targets[i].rank == rank)
            return &g_api.ht->targets[i];
    }
    return NULL;
}

static void dump_fill(wlapi_client_t *c) {
    const domain_hashtable_t *ht = g_api.ht;
    for (;;) {
        if (c->dump_rank < ht->target_count) {
            const ht_target_t *t = target_by_rank(c->dump_rank);
            if (t && out_fmt(c, "T %d %s\n", t->rank, t->name) < 0) return;
            c->dump_rank++;
            continue;
        }
        while (!c->dump_node && c->dump_bucket < DOMAIN_HT_BUCKETS)
            c->dump_node = ht->buckets[c->dump_bucket++];
        if (!c->dump_node) {
            if (out_fmt(c, "END %u\n", c->dumped) == 0) c->dumping = 0;
            return;
        }
        if (out_fmt(c, "K %s %d\n", c->dump_node->domain, c->dump_node->target->rank) == 0)
            c->dumped++;
        else if (c->out_len)
            return;
        c->dump_node = c->dump_node->next;
    }
}

static void answer_match(wlapi_client_t *c, char *name, size_t len) {
    if (len && name[len - 1] == '.') len--;
    if (len == 0 || len > WLAPI_NAME_MAX) {
        out_fmt(c, "ERR name\n");
        return;
    }
    to_lower_inplace(name, len);
    const char *key;
    const ht_target_t *t = watchlist_match(g_api.ht, name, len, &key);
    if (t)
        out_fmt(c, "OK %s %d %.*s\n", t->name, t->rank, (int)(name + len - key), key);
    else
        out_fmt(c, "NO\n");
}

static void answer(wlapi_client_t *c, char *line, size_t len) {
    if (len >= 6 && memcmp(line, "MATCH ", 6) == 0) {
        answer_match(c, line + 6, len - 6);
    } else if (strcmp(line, "DUMP") == 0) {
        c->dumping = 1;
        c->dump_rank = 0;
        c->dump_bucket = 0;
        c->dump_node = NULL;
        c->dumped = 0;
    } else {
        out_fmt(c, "ERR command\n");
    }
}

static void answer_requests(wlapi_client_t *c) {
    while (!c->dumping && WLAPI_OUT_BUF - c->out_len >= WLAPI_LINE_MAX) {
        char *nl = memchr(c->in, '\n', c->in_len);
        if (!nl) return;
        size_t len = (size_t)(nl - c->in);
        if (len && c->in[len - 1] == '\r') len--;
        c->in[len] = '\0';
        answer(c, c->in, len);
        c->in_len -= (size_t)(nl - c->in) + 1;
        memmove(c->in, nl + 1, c->in_len);
    }
}

static int client_read(wlapi_client_t *c) {
    while (!c->eof && c->in_len < WLAPI_IN_BUF) {
        ssize_t n = recv(c->fd, c->in + c->in_len, WLAPI_IN_BUF - c->in_len, 0);
        if (n > 0) {
            c->in_len += (size_t)n;
        } else if (n == 0) {
            c->eof = 1;
        } else if (errno != EINTR) {
            return errno == EAGAIN ? 0 : -1;
        }
    }
    return 0;
}

static int client_flush(wlapi_client_t *c) {
    while (c->out_off < c->out_len) {
        ssize_t n = send(c->fd, c->out + c->out_off, c->out_len - c->out_off, MSG_NOSIGNAL);
        if (n >= 0) {
            c->out_off += (size_t)n;
        } else if (errno != EINTR) {
            return errno == EAGAIN ? 0 : -1;
        }
    }
    c->out_off = c->out_len = 0;
    return 0;
}

static void client_close(wlapi_client_t *c) {
    close(c->fd);
    c->fd = -1;
}

static void client_event(wlapi_client_t *c, uint32_t events) {
    if ((events & EPOLLERR) || client_read(c) < 0 || client_flush(c) < 0) {
        client_close(c);
        return;
    }
    if (c->dumping) dump_fill(c);
    if (!c->dumping) answer_requests(c);
    if (client_flush(c) < 0) {
        client_close(c);
        return;
    }

    int has_line = memchr(c->in, '\n', c->in_len) != NULL;
    int idle = !c->dumping && !c->out_len && !has_line;
    if ((idle && c->eof) || (!has_line && c->in_len == WLAPI_IN_BUF)) {
        client_close(c);
        return;
    }

    uint32_t want = 0;
    if (!c->eof && c->in_len < WLAPI_IN_BUF) want |= EPOLLIN;
    if (!idle) want |= EPOLLOUT;
    if (want != c->events) {
        struct epoll_event ev = { .events = want, .data.ptr = c };
        if (epoll_ctl(g_api.epfd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
            client_close(c);
            return;
        }
        c->events = want;
    }
}

static void wlapi_accept(void) {
    int fd;
    while ((fd = accept4(g_api.listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)) >= 0) {
        wlapi_client_t *c = NULL;
        for (int i = 0; i < WLAPI_MAX_CLIENTS && !c; i++) {
            if (g_clients[i].fd < 0) c = &g_clients[i];
        }
        if (!c) {
            send(fd, "ERR busy\n", 9, MSG_NOSIGNAL);
            close(fd);
            continue;
        }
        c->fd = fd;
        c->events = EPOLLIN;
        c->eof = 0;
        c->dumping = 0;
        c->in_len = 0;
        c->out_off = c->out_len = 0;
        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = c };
        if (epoll_ctl(g_api.epfd, EPOLL_CTL_ADD, fd, &ev) < 0) client_close(c);
    }
}

static void *wlapi_loop(void *arg) {
    struct epoll_event events[WLAPI_MAX_CLIENTS + 2];
    for (;;) {
        int n = epoll_wait(g_api.epfd, events, WLAPI_MAX_CLIENTS + 2, -1);
        if (n < 0 && errno != EINTR) return NULL;
        for (int i = 0; i < n; i++) {
            void *p = events[i].data.ptr;
            if (p == &g_api.stop_fd) return NULL;
            if (p == &g_api.listen_fd) wlapi_accept();
            else client_event(p, events[i].events);
        }
    }
}

static void wlapi_release(void) {
    for (int i = 0; g_api.ht && i < WLAPI_MAX_CLIENTS; i++) {
        if (g_clients[i].fd >= 0) client_close(&g_clients[i]);
    }
    int *fds[] = { &g_api.listen_fd, &g_api.stop_fd, &g_api.epfd };
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
        if (*fds[i] >= 0) close(*fds[i]);
        *fds[i] = -1;
    }
    if (g_api.path[0]) unlink(g_api.path);
    g_api.path[0] = '\0';
}

static int epoll_add_ptr(int fd, void *ptr) {
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = ptr };
    return epoll_ctl(g_api.epfd, EPOLL_CTL_ADD, fd, &ev);
}

int wlapi_start(const char *path, const domain_hashtable_t *ht) {
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    size_t path_len = strlen(path);
    if (path_len >= sizeof(addr.sun_path)) {
        LOG_WARN("Watchlist API: socket path too long: %s", path);
        return -1;
    }
    memcpy(addr.sun_path, path, path_len + 1);

    g_api.ht = ht;
    for (int i = 0; i < WLAPI_MAX_CLIENTS; i++) g_clients[i].fd = -1;
    g_api.listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (g_api.listen_fd < 0) goto fail;
    unlink(path);
    if (bind(g_api.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) goto fail;
    memcpy(g_api.path, path, path_len + 1);
    if (chmod(path, 0600) < 0 || listen(g_api.listen_fd, WLAPI_MAX_CLIENTS) < 0) goto fail;

    g_api.epfd = epoll_create1(EPOLL_CLOEXEC);
    g_api.stop_fd = eventfd(0, EFD_CLOEXEC);
    if (g_api.epfd < 0 || g_api.stop_fd < 0 ||
        epoll_add_ptr(g_api.listen_fd, &g_api.listen_fd) < 0 ||
        epoll_add_ptr(g_api.stop_fd, &g_api.stop_fd) < 0)
        goto fail;

    sigset_t all, prev;
    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, &prev);
    int rc = pthread_create(&g_api.thread, NULL, wlapi_loop, NULL);
    pthread_sigmask(SIG_SETMASK, &prev, NULL);
    if (rc != 0) {
        errno = rc;
        goto fail;
    }

    g_api.running = 1;
    LOG_INFO("Watchlist API listening on %s", path);
    return 0;

fail:
    LOG_WARN("Watchlist API unavailable: %s: %s", path, strerror(errno));
    wlapi_release();
    return -1;
}

void wlapi_stop(void) {
    if (g_api.running) {
        eventfd_write(g_api.stop_fd, 1);
        pthread_join(g_api.thread, NULL);
        g_api.running = 0;
    }
    wlapi_release();
}

int wlapi_request(const char *path, const char *command, const char *arg) {
    char buf[WLAPI_OUT_BUF];
    int len = arg ? snprintf(buf, WLAPI_IN_BUF, "%s %s\n", command, arg)
                  : snprintf(buf, WLAPI_IN_BUF, "%s\n", command);
    if (len < 0 || len >= WLAPI_IN_BUF) {
        fprintf(stderr, "hrneo: request too long\n");
        return 2;
    }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        send(fd, buf, (size_t)len, MSG_NOSIGNAL) != len || shutdown(fd, SHUT_WR) < 0) {
        fprintf(stderr, "hrneo: watchlist API %s: %s\n", path, strerror(errno));
        if (fd >= 0) close(fd);
        return 2;
    }

    char last[3];
    size_t last_len = 0;
    int line_start = 1;
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0 || (n < 0 && errno == EINTR)) {
        if (n < 0) continue;
        fwrite(buf, 1, (size_t)n, stdout);
        for (ssize_t i = 0; i < n; i++) {
            if (line_start) last_len = 0;
            line_start = buf[i] == '\n';
            if (!line_start && last_len < sizeof(last)) last[last_len++] = buf[i];
        }
    }
    close(fd);

    if (!line_start) return 2;
    if (last_len >= 2 && memcmp(last, "OK", 2) == 0) return 0;
    if (last_len == 3 && memcmp(last, "END", 3) == 0) return 0;
    if (last_len == 2 && memcmp(last, "NO", 2) == 0) return 1;
    return 2;
}
