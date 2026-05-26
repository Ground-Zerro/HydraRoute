#include "../include/util.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

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

int ht_insert(domain_hashtable_t *ht, const char *domain, size_t domain_len, const char *ipset_name, int match_subs) {
    uint32_t h = fnv1a_hash(domain, domain_len) & (DOMAIN_HT_BUCKETS - 1);

    for (domain_node_t *node = ht->buckets[h]; node; node = node->next) {
        if (node->domain_len == domain_len && memcmp(node->domain, domain, domain_len) == 0)
            return 0;
    }

    domain_node_t *node = ht_pool_alloc(ht, sizeof(domain_node_t));
    if (!node) return -1;

    node->domain = ht_pool_strdup(ht, domain, domain_len);
    if (!node->domain) return -1;
    node->domain_len = domain_len;

    char *cached_ptr = NULL;
    for (int i = 0; i < ht->ipset_name_count; i++) {
        if (strcmp(ht->ipset_name_cache[i], ipset_name) == 0) {
            cached_ptr = ht->ipset_name_ptrs[i];
            break;
        }
    }

    if (cached_ptr) {
        node->entry.ipset_name = cached_ptr;
    } else {
        node->entry.ipset_name = ht_pool_strdup(ht, ipset_name, strlen(ipset_name));
        if (!node->entry.ipset_name) return -1;
        if (ht->ipset_name_count < MAX_POLICY_ORDER) {
            strncpy(ht->ipset_name_cache[ht->ipset_name_count], ipset_name, 63);
            ht->ipset_name_cache[ht->ipset_name_count][63] = '\0';
            ht->ipset_name_ptrs[ht->ipset_name_count] = node->entry.ipset_name;
            ht->ipset_name_count++;
        }
    }

    node->entry.match_subs = match_subs;
    node->next = ht->buckets[h];
    ht->buckets[h] = node;
    ht->count++;
    return 1;
}

domain_entry_t *ht_lookup(const domain_hashtable_t *ht, const char *domain, size_t domain_len) {
    uint32_t h = fnv1a_hash(domain, domain_len) & (DOMAIN_HT_BUCKETS - 1);
    for (domain_node_t *node = ht->buckets[h]; node; node = node->next) {
        if (node->domain_len == domain_len && memcmp(node->domain, domain, domain_len) == 0)
            return &node->entry;
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

int run_command_output(const char *cmd, char *const argv[], char *output, size_t output_size) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(cmd, argv);
        _exit(127);
    }

    close(pipefd[1]);
    size_t total = 0;
    ssize_t n;
    while (total < output_size - 1 && (n = read(pipefd[0], output + total, output_size - 1 - total)) > 0)
        total += n;
    output[total] = '\0';
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int run_command_stdin(const char *cmd, char *const argv[], const char *input, size_t input_len) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execvp(cmd, argv);
        _exit(127);
    }

    close(pipefd[0]);
    size_t written = 0;
    while (written < input_len) {
        ssize_t n = write(pipefd[1], input + written, input_len - written);
        if (n <= 0) break;
        written += n;
    }
    close(pipefd[1]);

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
