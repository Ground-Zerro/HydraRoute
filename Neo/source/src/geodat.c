#include "../include/geodat.h"
#include "../include/ipset_nl.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static int read_varint(const uint8_t *data, int len, int pos, uint64_t *out_val) {
    uint64_t val = 0;
    int shift = 0;
    int start = pos;

    while (pos < len) {
        uint8_t b = data[pos++];
        val |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            *out_val = val;
            return pos - start;
        }
        shift += 7;
        if (shift >= 64) return -1;
    }
    return -1;
}

static int read_varint_stream(FILE *f, uint64_t *out_val) {
    uint64_t val = 0;
    int shift = 0;
    int count = 0;

    while (1) {
        int b = fgetc(f);
        if (b == EOF) return -1;
        count++;
        val |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            *out_val = val;
            return count;
        }
        shift += 7;
        if (shift >= 64) return -1;
    }
}

static int parse_cidr_body(const uint8_t *data, int len, geoip_entry_t *entry) {
    memset(entry, 0, sizeof(*entry));
    int pos = 0;

    while (pos < len) {
        uint8_t tag = data[pos++];

        if (tag == 0x0A) {
            uint64_t ip_len;
            int br = read_varint(data, len, pos, &ip_len);
            if (br < 0) return -1;
            pos += br;
            if (ip_len != 4 && ip_len != 16) return -1;
            if (pos + (int)ip_len > len) return -1;
            memcpy(entry->ip, data + pos, ip_len);
            entry->ip_len = (uint8_t)ip_len;
            pos += ip_len;
        } else if (tag == 0x10) {
            uint64_t prefix;
            int br = read_varint(data, len, pos, &prefix);
            if (br < 0) return -1;
            pos += br;
            entry->prefix = (uint32_t)prefix;
        } else {
            int wire_type = tag & 0x07;
            if (wire_type == 0) {
                uint64_t dummy;
                int br = read_varint(data, len, pos, &dummy);
                if (br < 0) return -1;
                pos += br;
            } else if (wire_type == 2) {
                uint64_t flen;
                int br = read_varint(data, len, pos, &flen);
                if (br < 0) return -1;
                pos += br + (int)flen;
            } else {
                return -1;
            }
        }
    }

    int all_zero = 1;
    for (int i = 0; i < 16; i++) {
        if (entry->ip[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) return -1;

    return 0;
}

static int parse_geoip_body(const uint8_t *data, int len,
                            geoip_entry_t **entries, int *count, int *capacity) {
    int pos = 0;

    while (pos < len) {
        uint8_t tag = data[pos++];

        if (tag == 0x12) {
            uint64_t cidr_len;
            int br = read_varint(data, len, pos, &cidr_len);
            if (br < 0) break;
            pos += br;
            if (pos + (int)cidr_len > len) break;

            geoip_entry_t entry;
            if (parse_cidr_body(data + pos, (int)cidr_len, &entry) == 0) {
                if (*count >= *capacity) {
                    int new_cap = *capacity * 2;
                    geoip_entry_t *tmp = realloc(*entries, new_cap * sizeof(geoip_entry_t));
                    if (!tmp) break;
                    *entries = tmp;
                    *capacity = new_cap;
                }
                (*entries)[(*count)++] = entry;
            }
            pos += (int)cidr_len;
        } else {
            int wire_type = tag & 0x07;
            if (wire_type == 0) {
                uint64_t dummy;
                int br = read_varint(data, len, pos, &dummy);
                if (br < 0) break;
                pos += br;
            } else if (wire_type == 2) {
                uint64_t flen;
                int br = read_varint(data, len, pos, &flen);
                if (br < 0) break;
                pos += br + (int)flen;
                if (pos > len) break;
            } else {
                break;
            }
        }
    }
    return 0;
}

static void count_geoip_body(const uint8_t *data, int len, int *ipv4, int *ipv6) {
    int pos = 0;
    while (pos < len) {
        uint8_t tag = data[pos++];
        if (tag == 0x12) {
            uint64_t cidr_len;
            int br = read_varint(data, len, pos, &cidr_len);
            if (br < 0) break;
            pos += br;
            if (pos + (int)cidr_len > len) break;
            geoip_entry_t entry;
            if (parse_cidr_body(data + pos, (int)cidr_len, &entry) == 0) {
                if (entry.ip_len == 4) (*ipv4)++;
                else if (entry.ip_len == 16) (*ipv6)++;
            }
            pos += (int)cidr_len;
        } else {
            int wire_type = tag & 0x07;
            if (wire_type == 0) {
                uint64_t dummy;
                int br = read_varint(data, len, pos, &dummy);
                if (br < 0) break;
                pos += br;
            } else if (wire_type == 2) {
                uint64_t flen;
                int br = read_varint(data, len, pos, &flen);
                if (br < 0) break;
                pos += br + (int)flen;
                if (pos > len) break;
            } else {
                break;
            }
        }
    }
}

static int parse_geosite_domain(const uint8_t *data, int len, geosite_domain_t *domain) {
    domain->type = 0;
    domain->value = NULL;
    int pos = 0;

    while (pos < len) {
        uint8_t tag = data[pos++];

        if (tag == 0x08) {
            uint64_t type_val;
            int br = read_varint(data, len, pos, &type_val);
            if (br < 0) return -1;
            pos += br;
            domain->type = (uint32_t)type_val;
        } else if (tag == 0x12) {
            uint64_t val_len;
            int br = read_varint(data, len, pos, &val_len);
            if (br < 0) return -1;
            pos += br;
            if (pos + (int)val_len > len) return -1;
            domain->value = malloc(val_len + 1);
            memcpy(domain->value, data + pos, val_len);
            domain->value[val_len] = 0;
            pos += (int)val_len;
        } else {
            int wire_type = tag & 0x07;
            if (wire_type == 0) {
                uint64_t dummy;
                int br = read_varint(data, len, pos, &dummy);
                if (br < 0) return -1;
                pos += br;
            } else if (wire_type == 2) {
                uint64_t flen;
                int br = read_varint(data, len, pos, &flen);
                if (br < 0) return -1;
                pos += br + (int)flen;
                if (pos > len) return -1;
            } else {
                return -1;
            }
        }
    }
    return (domain->value != NULL) ? 0 : -1;
}

static int parse_geosite_body(const uint8_t *data, int len,
                              geosite_domain_t **domains, int *count, int *capacity) {
    int pos = 0;

    while (pos < len) {
        uint8_t tag = data[pos++];

        if (tag == 0x12) {
            uint64_t domain_len;
            int br = read_varint(data, len, pos, &domain_len);
            if (br < 0) break;
            pos += br;
            if (pos + (int)domain_len > len) break;

            geosite_domain_t entry;
            if (parse_geosite_domain(data + pos, (int)domain_len, &entry) == 0) {
                if (*count >= *capacity) {
                    int new_cap = *capacity * 2;
                    geosite_domain_t *tmp = realloc(*domains, new_cap * sizeof(geosite_domain_t));
                    if (!tmp) {
                        free(entry.value);
                        break;
                    }
                    *domains = tmp;
                    *capacity = new_cap;
                }
                (*domains)[(*count)++] = entry;
            }
            pos += (int)domain_len;
        } else {
            int wire_type = tag & 0x07;
            if (wire_type == 0) {
                uint64_t dummy;
                int br = read_varint(data, len, pos, &dummy);
                if (br < 0) break;
                pos += br;
            } else if (wire_type == 2) {
                uint64_t flen;
                int br = read_varint(data, len, pos, &flen);
                if (br < 0) break;
                pos += br + (int)flen;
                if (pos > len) break;
            } else {
                break;
            }
        }
    }
    return 0;
}

static void upcase_buf(char *dst, size_t dst_size, const char *src) {
    size_t n = 0;
    while (n + 1 < dst_size && src[n]) { dst[n] = src[n]; n++; }
    dst[n] = 0;
    for (char *p = dst; *p; p++)
        if (*p >= 'a' && *p <= 'z') *p -= 32;
}

typedef void (*dat_body_visitor_t)(const uint8_t *body, int body_len, void *ctx);

static int scan_dat_file(const char *file_path, const char *target_upper,
                          dat_body_visitor_t visit, void *ctx) {
    FILE *f = fopen(file_path, "rb");
    if (!f) return -1;
    setvbuf(f, NULL, _IOFBF, 64 * 1024);

    while (1) {
        int top_tag = fgetc(f);
        if (top_tag == EOF) break;
        if (top_tag != 0x0A) break;

        uint64_t body_len;
        if (read_varint_stream(f, &body_len) < 0) break;

        uint8_t *body = malloc(body_len);
        if (!body) break;
        if (fread(body, 1, body_len, f) != body_len) { free(body); break; }

        if (body_len < 2 || body[0] != 0x0A) { free(body); continue; }

        uint64_t code_len;
        int br = read_varint(body, (int)body_len, 1, &code_len);
        if (br < 0) { free(body); continue; }
        int code_start = 1 + br;
        if (code_start + (int)code_len > (int)body_len) { free(body); continue; }

        char code[64] = {0};
        size_t clen = code_len < sizeof(code) - 1 ? code_len : sizeof(code) - 1;
        memcpy(code, body + code_start, clen);
        for (char *p = code; *p; p++)
            if (*p >= 'a' && *p <= 'z') *p -= 32;

        if (strcmp(code, target_upper) == 0) {
            int data_pos = code_start + (int)code_len;
            visit(body + data_pos, (int)body_len - data_pos, ctx);
        }
        free(body);
    }

    fclose(f);
    return 0;
}

typedef struct {
    int *ipv4;
    int *ipv6;
} count_ctx_t;

static void count_geoip_visitor(const uint8_t *body, int len, void *ctx) {
    count_ctx_t *c = (count_ctx_t *)ctx;
    count_geoip_body(body, len, c->ipv4, c->ipv6);
}

static void count_geoip_cidrs_all_files(
    const char (*geoip_files)[512], int geoip_count,
    const char *tag, int *out_ipv4, int *out_ipv6)
{
    *out_ipv4 = 0;
    *out_ipv6 = 0;

    char target[64];
    upcase_buf(target, sizeof(target), tag);

    count_ctx_t ctx = { out_ipv4, out_ipv6 };
    for (int gi = 0; gi < geoip_count; gi++)
        scan_dat_file(geoip_files[gi], target, count_geoip_visitor, &ctx);
}

typedef struct {
    geoip_entry_t **entries;
    int *count;
    int *capacity;
} extract_geoip_ctx_t;

static void extract_geoip_visitor(const uint8_t *body, int len, void *ctx) {
    extract_geoip_ctx_t *c = (extract_geoip_ctx_t *)ctx;
    parse_geoip_body(body, len, c->entries, c->count, c->capacity);
}

static int extract_geoip_cidrs(const char *file_path, const char *country_code,
                               geoip_entry_t **out_entries, int *out_count) {
    char target[64];
    upcase_buf(target, sizeof(target), country_code);

    int capacity = 4096;
    *out_entries = malloc(capacity * sizeof(geoip_entry_t));
    if (!*out_entries) return -1;
    *out_count = 0;

    extract_geoip_ctx_t ctx = { out_entries, out_count, &capacity };
    int rc = scan_dat_file(file_path, target, extract_geoip_visitor, &ctx);
    if (rc != 0) LOG_WARN("GeoIP file not found: %s", file_path);
    return rc;
}

typedef struct {
    geosite_domain_t **domains;
    int *count;
    int *capacity;
} extract_geosite_ctx_t;

static void extract_geosite_visitor(const uint8_t *body, int len, void *ctx) {
    extract_geosite_ctx_t *c = (extract_geosite_ctx_t *)ctx;
    parse_geosite_body(body, len, c->domains, c->count, c->capacity);
}

static int extract_geosite_domains(const char *file_path, const char *tag,
                                   geosite_domain_t **out_domains, int *out_count) {
    char target[64];
    upcase_buf(target, sizeof(target), tag);

    int capacity = 4096;
    *out_domains = malloc(capacity * sizeof(geosite_domain_t));
    if (!*out_domains) return -1;
    *out_count = 0;

    extract_geosite_ctx_t ctx = { out_domains, out_count, &capacity };
    int rc = scan_dat_file(file_path, target, extract_geosite_visitor, &ctx);
    if (rc != 0) LOG_WARN("GeoSite file not found: %s", file_path);
    return rc;
}

typedef struct {
    int idx;
    int dots;
} dedup_entry_t;

static int compare_dots(const void *a, const void *b) {
    return ((const dedup_entry_t *)a)->dots - ((const dedup_entry_t *)b)->dots;
}

static int deduplicate_domains(const geosite_domain_t *domains, int count,
                               geosite_domain_t **output, int *out_count) {
    dedup_entry_t *entries = malloc(count * sizeof(dedup_entry_t));
    int entry_count = 0;

    for (int i = 0; i < count; i++) {
        if (domains[i].type != GEOSITE_TYPE_DOMAIN && domains[i].type != GEOSITE_TYPE_FULL)
            continue;
        int dots = 0;
        for (const char *p = domains[i].value; *p; p++) {
            if (*p == '.') dots++;
        }
        entries[entry_count++] = (dedup_entry_t){i, dots};
    }

    if (entry_count == 0) {
        free(entries);
        *output = NULL;
        *out_count = 0;
        return 0;
    }

    qsort(entries, entry_count, sizeof(dedup_entry_t), compare_dots);

    domain_hashtable_t *accepted = ht_create();

    *output = malloc(entry_count * sizeof(geosite_domain_t));
    *out_count = 0;

    domain_entry_t dummy_entry;
    memset(&dummy_entry, 0, sizeof(dummy_entry));

    for (int i = 0; i < entry_count; i++) {
        const char *val = domains[entries[i].idx].value;
        int covered = 0;

        const char *p = val;
        while (*p) {
            const char *dot = strchr(p, '.');
            if (!dot) break;
            p = dot + 1;
            if (ht_lookup(accepted, p, strlen(p))) {
                covered = 1;
                break;
            }
        }

        if (!covered) {
            ht_insert(accepted, val, strlen(val), "1", 0);
            (*output)[(*out_count)++] = domains[entries[i].idx];
        }
    }

    ht_destroy(accepted);
    free(entries);
    return 0;
}

int parse_geosite_rules(const char *watchlist_path,
                        geosite_rule_t *rules, int max_rules) {
    FILE *f = fopen(watchlist_path, "r");
    if (!f) return -1;

    int count = 0;
    char *line = NULL;
    size_t cap = 0;

    while (getline(&line, &cap, f) != -1 && count < max_rules) {
        line[strcspn(line, "\n\r")] = 0;
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (!*trimmed || *trimmed == '#') continue;

        char *last_slash = strrchr(trimmed, '/');
        if (!last_slash) continue;

        char policy[64] = {0};
        strncpy(policy, last_slash + 1, 63);
        char *comma = strchr(policy, ',');
        if (comma) *comma = 0;
        int plen = strlen(policy);
        while (plen > 0 && (policy[plen-1] == ' ' || policy[plen-1] == '\t'))
            policy[--plen] = 0;
        if (!plen) continue;

        *last_slash = 0;

        char *saveptr;
        char *token = strtok_r(trimmed, ",", &saveptr);
        while (token && count < max_rules) {
            while (*token == ' ' || *token == '\t') token++;
            if (strncmp(token, "geosite:", 8) == 0) {
                char *tag_str = token + 8;
                while (*tag_str == ' ') tag_str++;
                int tlen = strlen(tag_str);
                while (tlen > 0 && (tag_str[tlen-1] == ' ' || tag_str[tlen-1] == '\t'))
                    tlen--;
                if (tlen > 0) {
                    memset(&rules[count], 0, sizeof(geosite_rule_t));
                    int copy_len = tlen < MAX_TAG_LEN - 1 ? tlen : MAX_TAG_LEN - 1;
                    memcpy(rules[count].tag, tag_str, copy_len);
                    rules[count].tag[copy_len] = 0;
                    for (char *p = rules[count].tag; *p; p++) {
                        if (*p >= 'a' && *p <= 'z') *p -= 32;
                    }
                    strncpy(rules[count].policy_name, policy, MAX_POLICY_NAME - 1);
                    count++;
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    }

    free(line);
    fclose(f);
    return count;
}

int build_geosite_domain_map(const char (*file_paths)[512], int file_count,
                             const geosite_rule_t *rules, int rule_count,
                             domain_hashtable_t *ht) {
    if (rule_count == 0 || file_count == 0) return 0;

    int total_plain_skipped = 0;
    int total_regex_skipped = 0;

    for (int r = 0; r < rule_count; r++) {
        geosite_domain_t *all_domains = NULL;
        int all_count = 0;
        int found = 0;

        for (int fi = 0; fi < file_count; fi++) {
            geosite_domain_t *domains = NULL;
            int domain_count = 0;

            if (extract_geosite_domains(file_paths[fi], rules[r].tag,
                                        &domains, &domain_count) != 0) {
                continue;
            }

            if (domain_count > 0) found = 1;

            if (all_domains == NULL) {
                all_domains = domains;
                all_count = domain_count;
            } else {
                geosite_domain_t *tmp = realloc(all_domains,
                                                (all_count + domain_count) * sizeof(geosite_domain_t));
                if (!tmp) {
                    for (int i = 0; i < domain_count; i++) free(domains[i].value);
                    free(domains);
                } else {
                    all_domains = tmp;
                    memcpy(all_domains + all_count, domains, domain_count * sizeof(geosite_domain_t));
                    all_count += domain_count;
                    free(domains);
                }
            }
        }

        if (!found) {
            LOG_WARN("GeoSite: tag '%s' not found in any configured file", rules[r].tag);
            free(all_domains);
            continue;
        }

        int plain_skipped = 0, regex_skipped = 0, before_count = 0;
        for (int i = 0; i < all_count; i++) {
            if (all_domains[i].type == GEOSITE_TYPE_PLAIN) plain_skipped++;
            else if (all_domains[i].type == GEOSITE_TYPE_REGEX) regex_skipped++;
            else before_count++;
        }
        total_plain_skipped += plain_skipped;
        total_regex_skipped += regex_skipped;

        if (plain_skipped > 0)
            LOG_WARN("geosite:%s: %d Plain-type entries skipped", rules[r].tag, plain_skipped);
        if (regex_skipped > 0)
            LOG_WARN("geosite:%s: %d Regex-type entries skipped (not implemented)", rules[r].tag, regex_skipped);

        geosite_domain_t *deduped = NULL;
        int dedup_count = 0;
        deduplicate_domains(all_domains, all_count, &deduped, &dedup_count);

        LOG_DEBUG("geosite:%s: %d entries total, %d Domain/Full before dedup, %d after dedup",
                  rules[r].tag, all_count, before_count, dedup_count);

        for (int i = 0; i < dedup_count; i++) {
            const char *val = deduped[i].value;
            size_t vlen = strlen(val);

            if (deduped[i].type == GEOSITE_TYPE_FULL) {
                ht_insert(ht, val, vlen, rules[r].policy_name, 0);
            } else if (deduped[i].type == GEOSITE_TYPE_DOMAIN) {
                ht_insert(ht, val, vlen, rules[r].policy_name, 1);
            }
        }

        for (int i = 0; i < all_count; i++) {
            free(all_domains[i].value);
        }
        free(all_domains);
        free(deduped);
    }

    if (total_plain_skipped > 0 || total_regex_skipped > 0)
        LOG_WARN("GeoSite total: %d Plain and %d Regex entries skipped",
                 total_plain_skipped, total_regex_skipped);

    return 0;
}

static int parse_cidr_str(const char *str, parsed_cidr_t *out) {
    memset(out, 0, sizeof(*out));

    const char *slash = strchr(str, '/');
    if (!slash) return -1;

    char ip_str[64];
    int ip_len = (int)(slash - str);
    if (ip_len <= 0 || ip_len >= 64) return -1;
    memcpy(ip_str, str, ip_len);
    ip_str[ip_len] = 0;

    int prefix = atoi(slash + 1);

    if (strchr(ip_str, ':')) {
        uint8_t buf[16];
        if (inet_pton(AF_INET6, ip_str, buf) != 1) return -1;
        memcpy(out->ip, buf, 16);
        out->prefix = prefix;
        out->family = AF_INET6;
    } else {
        uint8_t buf[4];
        if (inet_pton(AF_INET, ip_str, buf) != 1) return -1;
        memcpy(out->ip, buf, 4);
        out->prefix = prefix;
        out->family = AF_INET;
    }
    return 0;
}

typedef struct {
    char tag[MAX_TAG_LEN];
    int  ipv4;
    int  ipv6;
} geoip_tag_count_t;

typedef struct {
    char set_name[64];
    int  count;
    int  warned;
} ipset_usage_t;

/* Open-addressed FNV-1a name → array index for batches[] and usage[].
 * Replaces O(n) linear scan; load factor stays well under 50% since
 * MAX_POLICY_ORDER * 2 = 128 and SLOT_COUNT = 256. */
#define NAME_INDEX_SLOTS 256

typedef struct {
    int      slot_idx[NAME_INDEX_SLOTS];   /* -1 = empty */
    uint32_t slot_hash[NAME_INDEX_SLOTS];
} name_index_t;

static void name_index_init(name_index_t *ni) {
    for (int i = 0; i < NAME_INDEX_SLOTS; i++) ni->slot_idx[i] = -1;
}

static int usage_index_lookup(const name_index_t *ni, const ipset_usage_t *usage,
                               uint32_t hash, const char *name) {
    uint32_t mask = NAME_INDEX_SLOTS - 1;
    for (uint32_t probe = 0; probe < NAME_INDEX_SLOTS; probe++) {
        uint32_t slot = (hash + probe) & mask;
        if (ni->slot_idx[slot] < 0) return -1;
        if (ni->slot_hash[slot] == hash &&
            strcmp(usage[ni->slot_idx[slot]].set_name, name) == 0)
            return ni->slot_idx[slot];
    }
    return -1;
}

static void name_index_insert(name_index_t *ni, uint32_t hash, int idx) {
    uint32_t mask = NAME_INDEX_SLOTS - 1;
    for (uint32_t probe = 0; probe < NAME_INDEX_SLOTS; probe++) {
        uint32_t slot = (hash + probe) & mask;
        if (ni->slot_idx[slot] < 0) {
            ni->slot_idx[slot] = idx;
            ni->slot_hash[slot] = hash;
            return;
        }
    }
}

static int usage_find_or_add(ipset_usage_t *usage, int *n, name_index_t *idx,
                              const char *name) {
    uint32_t hash = fnv1a_hash(name, strlen(name));
    int existing = usage_index_lookup(idx, usage, hash, name);
    if (existing >= 0) return existing;
    if (*n >= MAX_POLICY_ORDER * 2) return -1;
    strncpy(usage[*n].set_name, name, 63);
    usage[*n].set_name[63] = 0;
    usage[*n].count = 0;
    usage[*n].warned = 0;
    int new_idx = (*n)++;
    name_index_insert(idx, hash, new_idx);
    return new_idx;
}

#define CIDR_MIGRATE_MAX_LINES  16384
#define CIDR_MIGRATE_MAX_BLOCKS 512

typedef struct {
    char *text;
    int   keep;
    int   block_id;
} cidr_line_t;

static void free_cidr_lines(cidr_line_t *lines, int n) {
    for (int i = 0; i < n; i++) free(lines[i].text);
    free(lines);
}

static int cidrfile_migrate_oversized(
    const char *path,
    const geoip_tag_count_t *oversized, int oversized_count)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("Cannot open CIDRfile for migration: %s: %s", path, strerror(errno));
        return -1;
    }

    cidr_line_t *lines = malloc(CIDR_MIGRATE_MAX_LINES * sizeof(cidr_line_t));
    if (!lines) { fclose(f); return -1; }

    int line_count = 0;
    char *buf = NULL;
    size_t cap = 0;
    while (getline(&buf, &cap, f) != -1 && line_count < CIDR_MIGRATE_MAX_LINES) {
        buf[strcspn(buf, "\n\r")] = 0;
        lines[line_count].text = strdup(buf);
        if (!lines[line_count].text) { free(buf); free_cidr_lines(lines, line_count); fclose(f); return -1; }
        lines[line_count].keep = 1;
        lines[line_count].block_id = -1;
        line_count++;
    }
    free(buf);
    fclose(f);

    int block_active[CIDR_MIGRATE_MAX_BLOCKS];
    int block_header[CIDR_MIGRATE_MAX_BLOCKS];
    memset(block_active, 0, sizeof(block_active));
    memset(block_header, -1, sizeof(block_header));

    int current_block = -1;
    int next_block = 0;
    int in_active = 0;

    for (int i = 0; i < line_count; i++) {
        char *t = lines[i].text;
        while (*t == ' ' || *t == '\t') t++;

        if (t[0] == '\0' || strncmp(t, "##", 2) == 0) {
            current_block = -1;
            in_active = 0;
            continue;
        }
        if (strncmp(t, "#/", 2) == 0) {
            current_block = -1;
            in_active = 0;
            continue;
        }
        if (t[0] == '/') {
            if (next_block >= CIDR_MIGRATE_MAX_BLOCKS) { free_cidr_lines(lines, line_count); return -1; }
            current_block = next_block++;
            in_active = 1;
            block_header[current_block] = i;
            lines[i].block_id = current_block;
            continue;
        }
        if (!in_active || current_block < 0) continue;

        lines[i].block_id = current_block;

        if (strncmp(t, "geoip:", 6) == 0) {
            char *country = t + 6;
            while (*country == ' ') country++;
            int clen = strlen(country);
            while (clen > 0 && country[clen - 1] == ' ') clen--;

            char tag_upper[MAX_TAG_LEN] = {0};
            int tcopy = clen < MAX_TAG_LEN - 1 ? clen : MAX_TAG_LEN - 1;
            memcpy(tag_upper, country, tcopy);
            for (char *p = tag_upper; *p; p++)
                if (*p >= 'a' && *p <= 'z') *p -= 32;

            int is_over = 0;
            for (int o = 0; o < oversized_count; o++) {
                if (strcmp(oversized[o].tag, tag_upper) == 0) { is_over = 1; break; }
            }
            if (is_over)
                lines[i].keep = 0;
            else
                block_active[current_block]++;
        } else {
            block_active[current_block]++;
        }
    }

    for (int bid = 0; bid < next_block; bid++) {
        if (block_active[bid] > 0 || block_header[bid] < 0) continue;
        lines[block_header[bid]].keep = 0;
        for (int i = block_header[bid] - 1; i >= 0; i--) {
            char *t = lines[i].text;
            while (*t == ' ' || *t == '\t') t++;
            if (t[0] == '\0' || strncmp(t, "##", 2) == 0) {
                lines[i].keep = 0;
            } else {
                break;
            }
        }
    }

    char tmp_path[MAX_PATH_LEN + 16];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    FILE *out = fopen(tmp_path, "w");
    if (!out) {
        LOG_ERROR("Cannot create temp CIDRfile %s: %s", tmp_path, strerror(errno));
        free_cidr_lines(lines, line_count);
        return -1;
    }

    for (int i = 0; i < line_count; i++) {
        if (lines[i].keep)
            fprintf(out, "%s\n", lines[i].text);
    }
    free_cidr_lines(lines, line_count);

    fprintf(out, "\n##impossible to use\n");
    fprintf(out, "#/Too-big-geoip-tag\n");

    char written[256][MAX_TAG_LEN];
    int written_count = 0;
    for (int o = 0; o < oversized_count; o++) {
        int already = 0;
        for (int w = 0; w < written_count; w++) {
            if (strcmp(written[w], oversized[o].tag) == 0) { already = 1; break; }
        }
        if (already || written_count >= 256) continue;
        strncpy(written[written_count++], oversized[o].tag, MAX_TAG_LEN - 1);
        char lower[MAX_TAG_LEN] = {0};
        strncpy(lower, oversized[o].tag, MAX_TAG_LEN - 1);
        for (char *p = lower; *p; p++)
            if (*p >= 'A' && *p <= 'Z') *p += 32;
        fprintf(out, "geoip:%s\n", lower);
    }
    fclose(out);

    if (rename(tmp_path, path) != 0) {
        LOG_ERROR("Failed to rename %s to %s: %s", tmp_path, path, strerror(errno));
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

typedef struct {
    char name[64];
    int  has_v4;
    int  has_v6;
} cidr_block_t;

typedef void (*cidr_entry_fn)(const cidr_block_t *blk, const char *entry, void *ctx);

/* Generic block-aware scanner for CIDRfile. Walks lines, maintains the
 * /Name, ##, #/Name, empty-line state machine, and invokes on_entry for every
 * content line inside an active block (one whose name resolves to at least
 * one existing ipset). When verbose=1, emits LOG_DEBUG block-boundary lines. */
static int scan_cidrfile_blocks(const char *path, ipset_manager_t *mgr,
                                 cidr_entry_fn on_entry, void *ctx, int verbose) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char *line = NULL;
    size_t cap = 0;
    cidr_block_t blk;
    memset(&blk, 0, sizeof(blk));
    int is_active = 0;
    int in_block = 0;

    while (getline(&line, &cap, f) != -1) {
        line[strcspn(line, "\n\r")] = 0;
        char *t = line;
        while (*t == ' ' || *t == '\t') t++;

        if (t[0] == '\0' || strncmp(t, "##", 2) == 0) {
            if (verbose && in_block && blk.name[0])
                LOG_DEBUG("End of CIDR block: %s", blk.name);
            blk.name[0] = 0;
            blk.has_v4 = blk.has_v6 = 0;
            is_active = 0;
            in_block = 0;
            continue;
        }
        if (strncmp(t, "#/", 2) == 0) {
            if (verbose && in_block && blk.name[0])
                LOG_DEBUG("End of CIDR block: %s", blk.name);
            if (verbose)
                LOG_DEBUG("Disabled CIDR block: %s (skipping)", t + 2);
            blk.name[0] = 0;
            blk.has_v4 = blk.has_v6 = 0;
            is_active = 0;
            in_block = 1;
            continue;
        }
        if (t[0] == '/') {
            if (verbose && in_block && blk.name[0])
                LOG_DEBUG("End of CIDR block: %s", blk.name);
            char *name = t + 1;
            while (*name == ' ') name++;
            strncpy(blk.name, name, sizeof(blk.name) - 1);
            blk.name[sizeof(blk.name) - 1] = 0;
            int nlen = strlen(blk.name);
            while (nlen > 0 && (blk.name[nlen - 1] == ' ' || blk.name[nlen - 1] == '\t'))
                blk.name[--nlen] = 0;
            char v6n[64];
            snprintf(v6n, sizeof(v6n), "%.60sv6", blk.name);
            blk.has_v4 = ipset_set_exists(mgr, blk.name);
            blk.has_v6 = ipset_set_exists(mgr, v6n);
            is_active = blk.has_v4 || blk.has_v6;
            if (verbose) {
                if (is_active)
                    LOG_DEBUG("CIDR block start: %s (IPv4 %s, IPv6 %s)", blk.name,
                              blk.has_v4 ? "Y" : "N", blk.has_v6 ? "Y" : "N");
                else
                    LOG_DEBUG("CIDR block start: %s (skipped - no ipsets exist)", blk.name);
            }
            in_block = 1;
            continue;
        }

        if (!is_active || !blk.name[0]) continue;
        if (on_entry) on_entry(&blk, t, ctx);
    }
    free(line);
    fclose(f);
    return 0;
}

typedef struct {
    geoip_tag_count_t *tag_cache;
    int               *tag_cache_count;
    int                tag_cache_max;
    const char (*geoip_files)[512];
    int                geoip_count;
} phase1_ctx_t;

static void phase1_on_entry(const cidr_block_t *blk, const char *entry, void *ctx) {
    (void)blk;
    if (strncmp(entry, "geoip:", 6) != 0) return;
    phase1_ctx_t *cx = (phase1_ctx_t *)ctx;

    const char *country = entry + 6;
    while (*country == ' ') country++;
    int clen = strlen(country);
    while (clen > 0 && country[clen - 1] == ' ') clen--;

    char tag_upper[MAX_TAG_LEN] = {0};
    int tcopy = clen < MAX_TAG_LEN - 1 ? clen : MAX_TAG_LEN - 1;
    memcpy(tag_upper, country, tcopy);
    for (char *p = tag_upper; *p; p++)
        if (*p >= 'a' && *p <= 'z') *p -= 32;

    for (int k = 0; k < *cx->tag_cache_count; k++) {
        if (strcmp(cx->tag_cache[k].tag, tag_upper) == 0) return;
    }
    if (*cx->tag_cache_count >= cx->tag_cache_max) return;

    geoip_tag_count_t *tc = &cx->tag_cache[(*cx->tag_cache_count)++];
    strncpy(tc->tag, tag_upper, MAX_TAG_LEN - 1);
    tc->tag[MAX_TAG_LEN - 1] = 0;
    tc->ipv4 = 0;
    tc->ipv6 = 0;
    count_geoip_cidrs_all_files(cx->geoip_files, cx->geoip_count, tag_upper,
                                &tc->ipv4, &tc->ipv6);
}

typedef struct {
    char         set_name[64];
    parsed_cidr_t *entries;
    int           count;
    int           capacity;
} batch_t;

typedef struct {
    ipset_manager_t *mgr;
    const char (*geoip_files)[512];
    int              geoip_count;
    uint32_t         effective_limit;

    const geoip_tag_count_t *oversized;
    int                      oversized_count;
    const geoip_tag_count_t *tag_cache;
    int                      tag_cache_count;

    batch_t      *batches;
    int          *batch_count;
    int           batch_max;
    name_index_t *batch_index;

    ipset_usage_t *usage;
    int           *usage_count;
    name_index_t  *usage_index;
} phase2_ctx_t;

static int batches_index_lookup(const name_index_t *ni, const batch_t *batches,
                                 uint32_t hash, const char *name) {
    uint32_t mask = NAME_INDEX_SLOTS - 1;
    for (uint32_t probe = 0; probe < NAME_INDEX_SLOTS; probe++) {
        uint32_t slot = (hash + probe) & mask;
        if (ni->slot_idx[slot] < 0) return -1;
        if (ni->slot_hash[slot] == hash &&
            strcmp(batches[ni->slot_idx[slot]].set_name, name) == 0)
            return ni->slot_idx[slot];
    }
    return -1;
}

static int batch_find_or_add(batch_t *batches, int *count, int max,
                              name_index_t *idx, const char *set_name, int initial_cap) {
    uint32_t hash = fnv1a_hash(set_name, strlen(set_name));
    int existing = batches_index_lookup(idx, batches, hash, set_name);
    if (existing >= 0) return existing;
    if (*count >= max) return -1;
    int bi = (*count)++;
    strncpy(batches[bi].set_name, set_name, 63);
    batches[bi].set_name[63] = 0;
    batches[bi].capacity = initial_cap;
    batches[bi].entries = malloc(initial_cap * sizeof(parsed_cidr_t));
    batches[bi].count = 0;
    if (!batches[bi].entries) {
        (*count)--;
        return -1;
    }
    name_index_insert(idx, hash, bi);
    return bi;
}

static int batch_push(batch_t *b, const parsed_cidr_t *cidr) {
    if (b->count >= b->capacity) {
        int new_cap = b->capacity * 2;
        parsed_cidr_t *tmp = realloc(b->entries, new_cap * sizeof(parsed_cidr_t));
        if (!tmp) return -1;
        b->entries = tmp;
        b->capacity = new_cap;
    }
    b->entries[b->count++] = *cidr;
    return 0;
}

static void phase2_on_entry(const cidr_block_t *blk, const char *entry, void *ctx) {
    phase2_ctx_t *cx = (phase2_ctx_t *)ctx;
    const char *cur = blk->name;

    if (strncmp(entry, "geoip:", 6) == 0) {
        char country[MAX_TAG_LEN] = {0};
        const char *src = entry + 6;
        while (*src == ' ') src++;
        int clen = strlen(src);
        while (clen > 0 && src[clen - 1] == ' ') clen--;
        int ccopy = clen < MAX_TAG_LEN - 1 ? clen : MAX_TAG_LEN - 1;
        memcpy(country, src, ccopy);
        country[ccopy] = 0;

        if (cx->geoip_count == 0 || !cx->geoip_files) {
            LOG_WARN("GeoIP directive 'geoip:%s' found but GeoIPFile not configured", country);
            return;
        }

        char tag_upper[MAX_TAG_LEN] = {0};
        strncpy(tag_upper, country, MAX_TAG_LEN - 1);
        for (char *p = tag_upper; *p; p++)
            if (*p >= 'a' && *p <= 'z') *p -= 32;

        for (int o = 0; o < cx->oversized_count; o++) {
            if (strcmp(cx->oversized[o].tag, tag_upper) == 0) return;
        }

        int cached_ipv4 = -1, cached_ipv6 = -1;
        for (int k = 0; k < cx->tag_cache_count; k++) {
            if (strcmp(cx->tag_cache[k].tag, tag_upper) == 0) {
                cached_ipv4 = cx->tag_cache[k].ipv4;
                cached_ipv6 = cx->tag_cache[k].ipv6;
                break;
            }
        }

        char v4_target[64], v6_target[64];
        strncpy(v4_target, cur, 63);
        v4_target[63] = 0;
        snprintf(v6_target, sizeof(v6_target), "%.60sv6", cur);

        int allow_v4 = 1, allow_v6 = 1;

        if (cached_ipv4 > 0) {
            int ui = usage_find_or_add(cx->usage, cx->usage_count, cx->usage_index, v4_target);
            if (ui >= 0 && (uint32_t)(cx->usage[ui].count + cached_ipv4) > cx->effective_limit) {
                LOG_WARN("geoip:%s skipped for %s: %d + %d would exceed limit %u",
                         country, v4_target, cx->usage[ui].count, cached_ipv4, cx->effective_limit);
                allow_v4 = 0;
            }
        }
        if (cached_ipv6 > 0) {
            int ui = usage_find_or_add(cx->usage, cx->usage_count, cx->usage_index, v6_target);
            if (ui >= 0 && (uint32_t)(cx->usage[ui].count + cached_ipv6) > cx->effective_limit) {
                LOG_WARN("geoip:%s skipped for %s: %d + %d would exceed limit %u",
                         country, v6_target, cx->usage[ui].count, cached_ipv6, cx->effective_limit);
                allow_v6 = 0;
            }
        }
        if (!allow_v4 && !allow_v6) return;

        for (int gi = 0; gi < cx->geoip_count; gi++) {
            geoip_entry_t *entries = NULL;
            int entry_count = 0;

            if (extract_geoip_cidrs(cx->geoip_files[gi], country, &entries, &entry_count) != 0)
                continue;

            for (int e = 0; e < entry_count; e++) {
                char target_set[64];
                parsed_cidr_t cidr;
                memset(&cidr, 0, sizeof(cidr));

                if (entries[e].ip_len == 4) {
                    if (!allow_v4 || !ipset_set_exists(cx->mgr, cur)) continue;
                    strncpy(target_set, cur, 63);
                    target_set[63] = 0;
                    memcpy(cidr.ip, entries[e].ip, 4);
                    cidr.prefix = entries[e].prefix;
                    cidr.family = AF_INET;
                } else {
                    if (!allow_v6 || !ipset_set_exists(cx->mgr, v6_target)) continue;
                    strncpy(target_set, v6_target, 63);
                    target_set[63] = 0;
                    memcpy(cidr.ip, entries[e].ip, 16);
                    cidr.prefix = entries[e].prefix;
                    cidr.family = AF_INET6;
                }

                int bi = batch_find_or_add(cx->batches, cx->batch_count, cx->batch_max,
                                            cx->batch_index, target_set, 4096);
                if (bi >= 0) batch_push(&cx->batches[bi], &cidr);
            }
            free(entries);
        }

        if (allow_v4 && cached_ipv4 > 0) {
            int ui = usage_find_or_add(cx->usage, cx->usage_count, cx->usage_index, v4_target);
            if (ui >= 0) cx->usage[ui].count += cached_ipv4;
        }
        if (allow_v6 && cached_ipv6 > 0) {
            int ui = usage_find_or_add(cx->usage, cx->usage_count, cx->usage_index, v6_target);
            if (ui >= 0) cx->usage[ui].count += cached_ipv6;
        }
        return;
    }

    parsed_cidr_t cidr;
    if (parse_cidr_str(entry, &cidr) != 0) {
        LOG_WARN("Invalid CIDR: %s", entry);
        return;
    }

    char target_set[64];
    if (cidr.family == AF_INET) {
        if (!ipset_set_exists(cx->mgr, cur)) return;
        strncpy(target_set, cur, 63);
        target_set[63] = 0;
    } else {
        snprintf(target_set, sizeof(target_set), "%.60sv6", cur);
        if (!ipset_set_exists(cx->mgr, target_set)) return;
    }

    int ui = usage_find_or_add(cx->usage, cx->usage_count, cx->usage_index, target_set);
    if (ui >= 0 && (uint32_t)(cx->usage[ui].count + 1) > cx->effective_limit) {
        if (!cx->usage[ui].warned) {
            LOG_WARN("Static CIDR entries for %s reached limit %u, further entries skipped",
                     target_set, cx->effective_limit);
            cx->usage[ui].warned = 1;
        }
        return;
    }

    int bi = batch_find_or_add(cx->batches, cx->batch_count, cx->batch_max,
                                cx->batch_index, target_set, 256);
    if (bi >= 0 && batch_push(&cx->batches[bi], &cidr) == 0) {
        if (ui >= 0) cx->usage[ui].count++;
    }
}

int add_cidr_to_ipsets(ipset_manager_t *mgr, const char *cidr_path,
                       const ipset_pair_t *pairs, int pair_count,
                       int enable_timeout, int timeout,
                       const char (*geoip_files)[512], int geoip_count,
                       uint32_t maxelem)
{
    uint32_t effective_limit = (maxelem > 0) ? maxelem : IPSET_DEFAULT_MAXELEM;

    geoip_tag_count_t tag_cache[256];
    int tag_cache_count = 0;

    geoip_tag_count_t oversized[256];
    int oversized_count = 0;

    if (geoip_count > 0 && geoip_files) {
        phase1_ctx_t p1 = {
            .tag_cache = tag_cache,
            .tag_cache_count = &tag_cache_count,
            .tag_cache_max = 256,
            .geoip_files = geoip_files,
            .geoip_count = geoip_count,
        };
        if (scan_cidrfile_blocks(cidr_path, mgr, phase1_on_entry, &p1, 0) == 0) {
            for (int k = 0; k < tag_cache_count; k++) {
                if ((uint32_t)tag_cache[k].ipv4 > effective_limit ||
                    (uint32_t)tag_cache[k].ipv6 > effective_limit) {
                    LOG_WARN("geoip:%s: %d IPv4 + %d IPv6 CIDR exceeds limit %u, "
                             "migrating to disabled block",
                             tag_cache[k].tag, tag_cache[k].ipv4,
                             tag_cache[k].ipv6, effective_limit);
                    if (oversized_count < 256)
                        oversized[oversized_count++] = tag_cache[k];
                }
            }

            if (oversized_count > 0) {
                if (cidrfile_migrate_oversized(cidr_path, oversized, oversized_count) == 0)
                    LOG_INFO("CIDRfile updated: %d oversized tag(s) moved to disabled block",
                             oversized_count);
            }
        }
    }

    ipset_refresh_set_list(mgr);

    if (enable_timeout && timeout > 0) {
        uint32_t to = (uint32_t)timeout;
        for (int i = 0; i < pair_count; i++) {
            if (ipset_set_exists(mgr, pairs[i].ipv4))
                ipset_cache_timeout_for_set(mgr, pairs[i].ipv4, 1, to);
            if (ipset_set_exists(mgr, pairs[i].ipv6))
                ipset_cache_timeout_for_set(mgr, pairs[i].ipv6, 1, to);
        }
    }

    batch_t batches[MAX_POLICY_ORDER * 2];
    int batch_count = 0;
    name_index_t batch_index;
    name_index_init(&batch_index);

    ipset_usage_t usage[MAX_POLICY_ORDER * 2];
    int usage_count = 0;
    name_index_t usage_index;
    name_index_init(&usage_index);

    phase2_ctx_t p2 = {
        .mgr = mgr,
        .geoip_files = geoip_files,
        .geoip_count = geoip_count,
        .effective_limit = effective_limit,
        .oversized = oversized,
        .oversized_count = oversized_count,
        .tag_cache = tag_cache,
        .tag_cache_count = tag_cache_count,
        .batches = batches,
        .batch_count = &batch_count,
        .batch_max = MAX_POLICY_ORDER * 2,
        .batch_index = &batch_index,
        .usage = usage,
        .usage_count = &usage_count,
        .usage_index = &usage_index,
    };

    if (scan_cidrfile_blocks(cidr_path, mgr, phase2_on_entry, &p2, 1) != 0) {
        LOG_WARN("CIDR file not found: %s", cidr_path);
        return -1;
    }

    for (int i = 0; i < batch_count; i++) {
        if (batches[i].count == 0) {
            free(batches[i].entries);
            continue;
        }
        LOG_INFO("Adding %d entries to ipset %s", batches[i].count, batches[i].set_name);
        int new_count = 0;
        int new_indices[1];
        ipset_add_batch(mgr, batches[i].set_name,
                        batches[i].entries, batches[i].count,
                        0, &new_count, new_indices);
        free(batches[i].entries);
    }

    LOG_INFO("CIDR processing complete (processed %d ipsets)", batch_count);
    return 0;
}
