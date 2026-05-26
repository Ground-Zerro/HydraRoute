#ifndef ARGS_H
#define ARGS_H

#include "hrneo.h"
#include "config.h"
#include <stdint.h>

typedef struct {
    char config_path[MAX_PATH_LEN];
    char genconfig_target[MAX_PATH_LEN];

    /* Bit-per-parameter "was set on CLI" mask. Bit positions are owned by
     * the PARAMS[] table in params.c — do not test individual bits here. */
    uint32_t set_mask;

    int  auto_start;
    char watchlist_path[MAX_PATH_LEN];
    int  clear_ipset;
    int  cidr_enabled;
    char cidr_file_path[MAX_PATH_LEN];
    int  ipset_enable_timeout;
    int  ipset_timeout;
    char log_level[16];
    char log_file_path[MAX_PATH_LEN];
    int  direct_route_enabled;
    int  interface_fwmark_start;
    int  interface_table_start;
    int  global_routing;
    int  conntrack_flush;
    int  ipset_maxelem;
    char geo_ip_files[MAX_GEO_FILES][MAX_PATH_LEN];
    int  geo_ip_file_count;
    char geo_site_files[MAX_GEO_FILES][MAX_PATH_LEN];
    int  geo_site_file_count;
    char policy_order[MAX_POLICY_ORDER][64];
    int  policy_order_count;
    int  l7_capture_enabled;
    int  l7_queue_num;
    int  l7_enable_tls;
    int  l7_enable_http;
    int  l7_connbytes_max;
    char l7_wan_interface[MAX_INTERFACE_NAME];
    int  l7_tcp_reasm_enabled;
    int  l7_tcp_reasm_max_entries;
    int  l7_tcp_reasm_ttl_sec;
} cli_args_t;

int  args_parse(int argc, char *argv[], cli_args_t *out);
void args_apply(const cli_args_t *args, config_t *cfg);

#endif
