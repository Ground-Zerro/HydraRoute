#define _GNU_SOURCE
#include "../include/util.h"
#include "../include/log.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

#ifndef __NR_init_module
#error "init_module syscall not available in this libc"
#endif

static void *ht_pool_alloc(domain_hashtable_t *ht, size_t size) {
    size = (size + 7) & ~7;
    if (ht->pool_tail->used + size > POOL_CHUNK_SIZE) {
        pool_chunk_t *chunk = calloc(1, sizeof(pool_chunk_t));
        if (!chunk) return NULL;
        ht->pool_tail->next = chunk;
        ht->pool_tail = chunk;
    }
    void *ptr = ht->pool_tail->data + ht->pool_tail->used;
    ht->pool_tail->used += size;
    return ptr;
}

domain_hashtable_t *ht_create(void) {
    domain_hashtable_t *ht = calloc(1, sizeof(domain_hashtable_t));
    if (!ht) return NULL;
    pool_chunk_t *chunk = calloc(1, sizeof(pool_chunk_t));
    if (!chunk) {
        free(ht);
        return NULL;
    }
    ht->pool_head = ht->pool_tail = chunk;
    return ht;
}

void ht_destroy(domain_hashtable_t *ht) {
    if (!ht) return;
    pool_chunk_t *chunk = ht->pool_head;
    while (chunk) {
        pool_chunk_t *next = chunk->next;
        free(chunk);
        chunk = next;
    }
    free(ht);
}

static char *ht_pool_strdup(domain_hashtable_t *ht, const char *s, size_t len) {
    char *dst = ht_pool_alloc(ht, len + 1);
    if (!dst) return NULL;
    memcpy(dst, s, len);
    dst[len] = '\0';
    return dst;
}

static ht_target_t *ht_intern_target(domain_hashtable_t *ht, const char *name) {
    for (int i = 0; i < ht->target_count; i++) {
        if (strcmp(ht->targets[i].name, name) == 0)
            return &ht->targets[i];
    }
    if (ht->target_count == MAX_TARGETS) return NULL;
    ht_target_t *target = &ht->targets[ht->target_count++];
    snprintf(target->name, sizeof(target->name), "%s", name);
    target->rank = MAX_TARGETS;
    return target;
}

void ht_rank_targets(domain_hashtable_t *ht, const char (*order)[64], int count) {
    for (int i = 0; i < count; i++) {
        ht_target_t *target = ht_intern_target(ht, order[i]);
        if (target) target->rank = i;
    }
}

int ht_insert(domain_hashtable_t *ht, const char *domain, size_t domain_len, const char *ipset_name) {
    uint32_t h = fnv1a_hash(domain, domain_len) & (DOMAIN_HT_BUCKETS - 1);

    for (domain_node_t *node = ht->buckets[h]; node; node = node->next) {
        if (node->domain_len == domain_len && memcmp(node->domain, domain, domain_len) == 0)
            return 0;
    }

    const ht_target_t *target = ht_intern_target(ht, ipset_name);
    if (!target) return -1;

    domain_node_t *node = ht_pool_alloc(ht, sizeof(domain_node_t));
    if (!node) return -1;

    node->domain = ht_pool_strdup(ht, domain, domain_len);
    if (!node->domain) return -1;
    node->domain_len = domain_len;

    node->target = target;
    node->next = ht->buckets[h];
    ht->buckets[h] = node;
    ht->count++;
    return 1;
}

const ht_target_t *ht_lookup(const domain_hashtable_t *ht, const char *domain, size_t domain_len) {
    uint32_t h = fnv1a_hash(domain, domain_len) & (DOMAIN_HT_BUCKETS - 1);
    for (domain_node_t *node = ht->buckets[h]; node; node = node->next) {
        if (node->domain_len == domain_len && memcmp(node->domain, domain, domain_len) == 0)
            return node->target;
    }
    return NULL;
}

void to_lower_inplace(char *s, size_t len) {
    for (size_t i = 0; i < len; i++)
        s[i] = (char)tolower((unsigned char)s[i]);
}

char *trim_whitespace(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return s;
}

int mkdir_p(const char *path, int mode) {
    char tmp[MAX_PATH_LEN];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return -1;
    memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int reap_child(pid_t pid, const char *cmd, int64_t deadline) {
    int status;
    while (waitpid(pid, &status, WNOHANG) == 0) {
        if (mono_ms() >= deadline) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            LOG_WARN("%s: no exit within %d ms, killed", cmd, CHILD_DEADLINE_MS);
            return -1;
        }
        usleep(1000);
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_child(const char *cmd, char *const argv[], const char *input, size_t input_len,
                     char *output, size_t output_size) {
    int out[2], in[2] = {-1, -1};
    if (pipe2(out, O_CLOEXEC) < 0) return -1;
    if (input && (pipe2(in, O_CLOEXEC) < 0 || fcntl(in[1], F_SETFL, O_NONBLOCK) < 0)) {
        close(out[0]);
        close(out[1]);
        if (in[0] >= 0) { close(in[0]); close(in[1]); }
        return -1;
    }

    pid_t pid = fork();
    if (pid == 0) {
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        signal(SIGPIPE, SIG_DFL);
        if (input) dup2(in[0], STDIN_FILENO);
        dup2(out[1], STDOUT_FILENO);
        dup2(out[1], STDERR_FILENO);
        execvp(cmd, argv);
        _exit(127);
    }
    close(out[1]);
    if (input) close(in[0]);
    if (pid < 0) {
        close(out[0]);
        if (input) close(in[1]);
        return -1;
    }

    int64_t deadline = mono_ms() + CHILD_DEADLINE_MS;
    int wfd = input ? in[1] : -1;
    size_t written = 0, total = 0;
    int truncated = 0, expired = 0;
    char sink[512];
    for (;;) {
        if (wfd >= 0 && written == input_len) {
            close(wfd);
            wfd = -1;
        }
        int64_t left = deadline - mono_ms();
        if (left <= 0) {
            expired = 1;
            break;
        }
        struct pollfd p[2] = {{out[0], POLLIN, 0}, {wfd, POLLOUT, 0}};
        if (poll(p, 2, (int)left) < 0) {
            if (errno == EINTR) continue;
            expired = 1;
            break;
        }
        if (p[1].revents) {
            ssize_t w = write(wfd, input + written, input_len - written);
            if (w > 0) written += (size_t)w;
            else if (errno != EAGAIN) written = input_len;
        }
        if (!p[0].revents) continue;
        int to_output = output && total < output_size - 1;
        ssize_t r = read(out[0], to_output ? output + total : sink,
                         to_output ? output_size - 1 - total : sizeof(sink));
        if (r <= 0) break;
        if (to_output) total += (size_t)r;
        else if (output) truncated = 1;
    }
    if (wfd >= 0) close(wfd);
    close(out[0]);
    if (output) output[total] = '\0';

    if (expired) deadline = mono_ms();
    int rc = reap_child(pid, cmd, deadline);
    return truncated ? -1 : rc;
}

int run_command_output(const char *cmd, char *const argv[], char *output, size_t output_size) {
    return run_child(cmd, argv, NULL, 0, output, output_size);
}

const char *line_find(const char *line, size_t line_len, const char *needle) {
    size_t nlen = strlen(needle);
    if (nlen > line_len) return NULL;
    for (size_t i = 0; i + nlen <= line_len; i++) {
        if (memcmp(line + i, needle, nlen) == 0) return line + i;
    }
    return NULL;
}

int run_command_stdin(const char *cmd, char *const argv[], const char *input, size_t input_len) {
    return run_child(cmd, argv, input, input_len, NULL, 0);
}

static int module_already_loaded(const char *name) {
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;
    char line[256];
    size_t name_len = strlen(name);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, name_len) == 0 &&
            (line[name_len] == ' ' || line[name_len] == '\t')) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int find_kmod_path(const char *name, char *out, size_t out_size) {
    struct utsname un;
    if (uname(&un) < 0) return -1;

    snprintf(out, out_size, "/lib/modules/%s/%s.ko", un.release, name);
    struct stat st;
    if (stat(out, &st) == 0) return 0;
    return -1;
}

int thread_start_masked(pthread_t *thread, void *(*fn)(void *)) {
    sigset_t all, prev;
    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, &prev);
    int rc = pthread_create(thread, NULL, fn, NULL);
    pthread_sigmask(SIG_SETMASK, &prev, NULL);
    return rc;
}

int load_kmod(const char *module_name) {
    if (module_already_loaded(module_name)) {
        LOG_DEBUG("kmod %s already loaded", module_name);
        return 0;
    }

    char path[512];
    if (find_kmod_path(module_name, path, sizeof(path)) != 0) {
        LOG_WARN("kmod %s: file not found under /lib/modules", module_name);
        return -1;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_WARN("kmod %s: open %s: %s", module_name, path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        close(fd);
        LOG_WARN("kmod %s: fstat failed", module_name);
        return -1;
    }

    size_t sz = (size_t)st.st_size;
    void *buf = malloc(sz);
    if (!buf) { close(fd); return -1; }

    size_t total = 0;
    while (total < sz) {
        ssize_t n = read(fd, (char *)buf + total, sz - total);
        if (n <= 0) { free(buf); close(fd); return -1; }
        total += (size_t)n;
    }
    close(fd);

    long rc = syscall(__NR_init_module, buf, (unsigned long)sz, "");
    int saved_errno = errno;
    free(buf);

    if (rc < 0 && saved_errno != EEXIST) {
        LOG_WARN("kmod %s: init_module failed: %s", module_name, strerror(saved_errno));
        return -1;
    }
    LOG_INFO("kmod %s loaded", module_name);
    return 0;
}
