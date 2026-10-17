#include "../include/config.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define CONF_PATH "build/check_config.conf"

static void check_empty_geo_files_ignored(void) {
    FILE *f = fopen(CONF_PATH, "w");
    assert(f);
    fputs("GeoIPFile=\nGeoSiteFile=\nGeoSiteFile=/opt/geosite.dat\nGeoSiteFile=\n", f);
    fclose(f);

    config_t cfg;
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(cfg.geo_ip_file_count == 0);
    assert(cfg.geo_site_file_count == 1);
    assert(strcmp(cfg.geo_site_files[0], "/opt/geosite.dat") == 0);
    remove(CONF_PATH);
}

static void check_nflog_group_range(void) {
    static const struct { const char *val; int expect; } cases[] = {
        {"1", 1}, {"65535", 65535}, {"70000", 210}, {"0", 210}, {"-5", 210},
        {"4294967506", 210},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        FILE *f = fopen(CONF_PATH, "w");
        assert(f);
        fprintf(f, "l7NflogGroup=%s\nIpsetTimeout=4294967296\n", cases[i].val);
        fclose(f);
        config_t cfg;
        assert(config_read(CONF_PATH, &cfg) == 0);
        assert(cfg.l7_nflog_group == cases[i].expect);
        assert(cfg.ipset_timeout == 21600);
    }
    remove(CONF_PATH);
}

int main(void) {
    check_empty_geo_files_ignored();
    check_nflog_group_range();
    printf("check_config: OK\n");
    return 0;
}
