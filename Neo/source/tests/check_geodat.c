#include "../include/geodat.h"
#include "../include/util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static size_t put_varint(uint8_t *p, uint64_t v) {
    size_t n = 0;
    while (v >= 0x80) { p[n++] = (uint8_t)(v | 0x80); v >>= 7; }
    p[n++] = (uint8_t)v;
    return n;
}

static size_t put_bytes(uint8_t *p, uint8_t tag, const void *data, uint64_t declared, size_t len) {
    size_t n = 0;
    p[n++] = tag;
    n += put_varint(p + n, declared);
    memcpy(p + n, data, len);
    return n + len;
}

static size_t geosite_entry(uint8_t *p, const char *code, uint64_t code_decl,
                            const char *domain, uint64_t domain_decl) {
    uint8_t dom[300], body[600];
    size_t dn = 0, bn = 0;
    dom[dn++] = 0x08;
    dom[dn++] = 2;
    dn += put_bytes(dom + dn, 0x12, domain, domain_decl, strlen(domain));
    bn += put_bytes(body + bn, 0x0A, code, code_decl, strlen(code));
    bn += put_bytes(body + bn, 0x12, dom, dn, dn);
    return put_bytes(p, 0x0A, body, bn, bn);
}

static void write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    assert(f);
    assert(fwrite(data, 1, len, f) == len);
    fclose(f);
}

static int load(const char *path, const char *tag, const char *probe) {
    char files[1][512];
    snprintf(files[0], sizeof(files[0]), "%s", path);
    geosite_rule_t rule;
    memset(&rule, 0, sizeof(rule));
    snprintf(rule.tag, sizeof(rule.tag), "%s", tag);
    snprintf(rule.policy_name, sizeof(rule.policy_name), "HR");
    domain_hashtable_t *ht = ht_create();
    build_geosite_domain_map((const char (*)[512])files, 1, &rule, 1, ht);
    int found = ht_lookup(ht, probe, strlen(probe)) != NULL;
    ht_destroy(ht);
    return found;
}

int main(void) {
    char path[] = "/tmp/check_geodat_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    alarm(5);

    uint8_t buf[4096];
    size_t n = 0;
    n += geosite_entry(buf + n, "other", 5, "skip.example", 12);
    n += geosite_entry(buf + n, "test", 4, "example.com", 11);
    write_file(path, buf, n);
    assert(load(path, "TEST", "example.com"));
    assert(!load(path, "TEST", "skip.example"));
    assert(!load(path, "TES", "example.com"));

    n = geosite_entry(buf, "test", 0xFFFFFFFFu, "example.com", 11);
    write_file(path, buf, n);
    assert(!load(path, "TEST", "example.com"));

    n = geosite_entry(buf, "test", 4, "example.com", 0xFFFFFFFAu);
    write_file(path, buf, n);
    assert(!load(path, "TEST", "example.com"));

    n = 0;
    buf[n++] = 0x0A;
    n += put_varint(buf + n, 0xFFFFFFFFFFFFull);
    n += geosite_entry(buf + n, "test", 4, "example.com", 11);
    write_file(path, buf, n);
    assert(!load(path, "TEST", "example.com"));

    unlink(path);
    puts("check_geodat: OK");
    return 0;
}
