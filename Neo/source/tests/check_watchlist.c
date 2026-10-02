#include "../include/watchlist.h"
#include "../include/util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const dns_cname_t CHAIN[] = {
    { "www.example.com", "www.example.com.edge.example.org" },
    { "www.example.com.edge.example.org", "www.example.com.cdn.cloudflare.net" },
};
static const char *const A_OWNER = "www.example.com.cdn.cloudflare.net";

static domain_hashtable_t *load(const char *watch_domain, const char *watch_target,
                                const char *geo_domain, const char *geo_target,
                                const char (*order)[64], int order_count) {
    domain_hashtable_t *ht = ht_create();
    ht_insert(ht, watch_domain, strlen(watch_domain), watch_target);

    char names[MAX_TARGETS][64];
    int count = get_unique_names(ht, names, MAX_TARGETS);
    snprintf(names[count++], 64, "%s", geo_target);
    sort_policies(names, count, order, order_count);
    ht_rank_targets(ht, (const char (*)[64])names, count);

    ht_insert(ht, geo_domain, strlen(geo_domain), geo_target);
    return ht;
}

static void expect_cname(const char (*order)[64], int order_count,
                         const char *target, const char *via) {
    domain_hashtable_t *ht = load("example.com", "Airnet", "cloudflare.net", "CF",
                                  order, order_count);
    const char *matched = NULL;
    assert(strcmp(match_domain_with_cname(ht, A_OWNER, CHAIN, 2, &matched), target) == 0);
    assert(strcmp(matched, via) == 0);
    ht_destroy(ht);
}

static void expect_subdomain(const char (*order)[64], int order_count, const char *target) {
    domain_hashtable_t *ht = load("google.com", "CN", "mail.google.com", "RU",
                                  order, order_count);
    assert(strcmp(match_domain_with_cname(ht, "mail.google.com", NULL, 0, NULL), target) == 0);
    ht_destroy(ht);
}

int main(void) {
    static const char airnet_cf[][64] = { "Airnet", "CF" };
    static const char cf[][64] = { "CF" };
    static const char ru[][64] = { "RU" };

    expect_cname(airnet_cf, 2, "Airnet", "www.example.com");
    expect_cname(cf, 1, "CF", A_OWNER);
    expect_cname(NULL, 0, "Airnet", "www.example.com");

    expect_subdomain(NULL, 0, "CN");
    expect_subdomain(ru, 1, "RU");

    printf("check_watchlist: OK\n");
    return 0;
}
