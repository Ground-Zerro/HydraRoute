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

int main(void) {
    check_empty_geo_files_ignored();
    printf("check_config: OK\n");
    return 0;
}
