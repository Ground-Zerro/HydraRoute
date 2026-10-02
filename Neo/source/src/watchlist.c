#include "../include/watchlist.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int parse_watchlist_lines(const char *path,
                          watchlist_target_fn on_target,
                          watchlist_domain_fn on_domain,
                          void *user) {
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("Cannot open watchlist: %s", path);
        return -1;
    }

    char *line = NULL;
    size_t cap = 0;
    while (getline(&line, &cap, f) != -1) {
        char *trimmed = trim_whitespace(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#')
            continue;

        char *last_slash = strrchr(trimmed, '/');
        if (!last_slash)
            continue;

        char *target = trim_whitespace(last_slash + 1);
        char *comma_in_target = strchr(target, ',');
        if (comma_in_target)
            *comma_in_target = '\0';
        target = trim_whitespace(target);
        if (target[0] == '\0')
            continue;

        char target_buf[64];
        strncpy(target_buf, target, sizeof(target_buf) - 1);
        target_buf[sizeof(target_buf) - 1] = '\0';

        if (on_target && on_target(target_buf, user) == 0)
            continue;

        *last_slash = '\0';

        char *saveptr;
        char *token = strtok_r(trimmed, ",", &saveptr);
        while (token) {
            char *domain = trim_whitespace(token);
            if (domain[0] != '\0' && strncmp(domain, "geosite:", 8) != 0) {
                size_t dlen = strlen(domain);
                to_lower_inplace(domain, dlen);
                if (on_domain) on_domain(target_buf, domain, dlen, user);
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }

    free(line);
    fclose(f);
    return 0;
}

static void watchlist_insert_domain(const char *target, const char *domain,
                                    size_t dlen, void *user) {
    ht_insert((domain_hashtable_t *)user, domain, dlen, target);
}

int parse_watchlist(const char *path, domain_hashtable_t *ht) {
    int rc = parse_watchlist_lines(path, NULL, watchlist_insert_domain, ht);
    if (rc != 0) return rc;
    LOG_INFO("Watchlist loaded: %d entries from %s", ht->count, path);
    return 0;
}

int get_unique_names(const domain_hashtable_t *ht, char names[][64], int max_names) {
    int count = ht->target_count < max_names ? ht->target_count : max_names;
    for (int i = 0; i < count; i++)
        memcpy(names[i], ht->targets[i].name, 64);
    return count;
}

static int get_policy_priority(const char (*policy_order)[64], int order_count, const char *name) {
    for (int i = 0; i < order_count; i++) {
        if (strcmp(policy_order[i], name) == 0)
            return i;
    }
    return order_count;
}

typedef struct {
    int priority;
    char name[64];
} policy_sort_entry_t;

static int cmp_policy_entry(const void *a, const void *b) {
    const policy_sort_entry_t *pa = (const policy_sort_entry_t *)a;
    const policy_sort_entry_t *pb = (const policy_sort_entry_t *)b;
    if (pa->priority != pb->priority)
        return pa->priority - pb->priority;
    return strcmp(pa->name, pb->name);
}

void sort_policies(char names[][64], int count, const char order[][64], int order_count) {
    if (count <= 0 || count > MAX_TARGETS)
        return;

    policy_sort_entry_t entries[MAX_TARGETS];
    for (int i = 0; i < count; i++) {
        entries[i].priority = get_policy_priority(order, order_count, names[i]);
        memcpy(entries[i].name, names[i], 64);
    }

    for (int i = 0; i < order_count; i++) {
        int found = 0;
        for (int j = 0; j < count; j++) {
            if (strcmp(names[j], order[i]) == 0) {
                found = 1;
                break;
            }
        }
        if (!found)
            LOG_WARN("PolicyOrder: policy '%s' not found, skipping", order[i]);
    }

    qsort(entries, count, sizeof(entries[0]), cmp_policy_entry);

    for (int i = 0; i < count; i++)
        memcpy(names[i], entries[i].name, 64);
}

const ht_target_t *watchlist_match(const domain_hashtable_t *ht,
                                   const char *domain, size_t domain_len,
                                   const char **key) {
    const ht_target_t *best = ht_lookup(ht, domain, domain_len);
    const char *best_key = domain;

    for (size_t i = 0; i < domain_len; i++) {
        if (domain[i] == '.') {
            const char *suffix = domain + i + 1;
            size_t suffix_len = domain_len - i - 1;
            if (suffix_len == 0) continue;
            const ht_target_t *target = ht_lookup(ht, suffix, suffix_len);
            if (target && (!best || target->rank < best->rank)) {
                best = target;
                best_key = suffix;
            }
        }
    }

    if (key) *key = best_key;
    return best;
}

const char *match_domain_with_cname(const domain_hashtable_t *ht,
                                    const char *domain,
                                    const dns_cname_t *cnames, int cname_count,
                                    const char **matched_domain) {
    const char *queue[MAX_CNAME_CHAIN];
    uint32_t visited_hashes[MAX_CNAME_CHAIN];
    int head = 0, tail = 0, visited_count = 0;
    const ht_target_t *best = NULL;

    queue[tail++] = domain;

    while (head < tail && head < MAX_CNAME_CHAIN) {
        const char *current = queue[head++];
        size_t cur_len = strlen(current);
        uint32_t h = fnv1a_hash(current, cur_len);

        int was_visited = 0;
        for (int i = 0; i < visited_count; i++) {
            if (visited_hashes[i] == h) { was_visited = 1; break; }
        }
        if (was_visited) continue;
        if (visited_count < MAX_CNAME_CHAIN)
            visited_hashes[visited_count++] = h;

        const ht_target_t *target = watchlist_match(ht, current, cur_len, NULL);
        if (target && (!best || target->rank < best->rank)) {
            best = target;
            if (matched_domain) *matched_domain = current;
            if (target->rank == 0) break;
        }

        for (int i = 0; i < cname_count; i++) {
            if (strcmp(cnames[i].source, current) == 0) {
                if (tail < MAX_CNAME_CHAIN) queue[tail++] = cnames[i].target;
            }
            if (strcmp(cnames[i].target, current) == 0) {
                if (tail < MAX_CNAME_CHAIN) queue[tail++] = cnames[i].source;
            }
        }
    }

    return best ? best->name : NULL;
}
