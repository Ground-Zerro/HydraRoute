#include "../include/params.h"
#include "../include/util.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define BIT(n) ((uint32_t)1u << (n))

const param_def_t PARAMS[] = {
    { "autoStart",            "--autoStart",            PT_BOOL,
      offsetof(config_t, auto_start),             0,
      BIT(0),  0,            1,
      "<true|false>",            "Allow daemon startup",                       "true"  },

    { "watchlistPath",        "--watchlistPath",        PT_PATH,
      offsetof(config_t, watchlist_path),         0,
      BIT(1),  MAX_PATH_LEN, 0,
      "<path>",                  "Path to domain watchlist file",
      "/opt/etc/HydraRoute/domain.conf" },

    { "clearIPSet",           "--clearIPSet",           PT_BOOL,
      offsetof(config_t, clear_ipset),            0,
      BIT(2),  0,            1,
      "<true|false>",            "Flush ipsets on startup",                    "true"  },

    { "CIDR",                 "--CIDR",                 PT_BOOL,
      offsetof(config_t, cidr_enabled),           0,
      BIT(3),  0,            1,
      "<true|false>",            "Enable loading static CIDR blocks",          "true"  },

    { "CIDRfile",             "--CIDRfile",             PT_PATH,
      offsetof(config_t, cidr_file_path),         0,
      BIT(4),  MAX_PATH_LEN, 0,
      "<path>",                  "Path to CIDR list file",
      "/opt/etc/HydraRoute/ip.list" },

    { "IpsetEnableTimeout",   "--IpsetEnableTimeout",   PT_BOOL,
      offsetof(config_t, ipset_enable_timeout),   0,
      BIT(5),  0,            1,
      "<true|false>",            "Enable ipset entry timeout",                 "true"  },

    { "IpsetTimeout",         "--IpsetTimeout",         PT_INT,
      offsetof(config_t, ipset_timeout),          0,
      BIT(6),  0,            21600,
      "<seconds>",               "Entry timeout in seconds (e.g. 21600 = 6h)", "21600" },

    { "log",                  "--log",                  PT_STRING,
      offsetof(config_t, log_level),              0,
      BIT(7),  16,           0,
      "<console|file|syslog|off>", "Log output mode",                          "off"   },

    { "logfile",              "--logfile",              PT_PATH,
      offsetof(config_t, log_file_path),          0,
      BIT(8),  MAX_PATH_LEN, 0,
      "<path>",                  "Log file path (used with --log file)",
      "/opt/var/log/LOGhrneo.log" },

    { "DirectRouteEnabled",   "--DirectRouteEnabled",   PT_BOOL,
      offsetof(config_t, direct_route_enabled),   0,
      BIT(9),  0,            1,
      "<true|false>",            "Enable direct interface routing",            "true"  },

    { "InterfaceFwMarkStart", "--InterfaceFwMarkStart", PT_INT_POS,
      offsetof(config_t, interface_fwmark_start), 0,
      BIT(10), 0,            12289,
      "<int>",                   "Starting fwmark value",                      "12289" },

    { "InterfaceTableStart",  "--InterfaceTableStart",  PT_INT_POS,
      offsetof(config_t, interface_table_start),  0,
      BIT(11), 0,            301,
      "<int>",                   "Starting routing table ID",                  "301"   },

    { "GlobalRouting",        "--GlobalRouting",        PT_BOOL,
      offsetof(config_t, global_routing),         0,
      BIT(12), 0,            0,
      "<true|false>",            "Override router policies for all traffic",   "false" },

    { "ConntrackFlush",       "--ConntrackFlush",       PT_BOOL,
      offsetof(config_t, conntrack_flush),        0,
      BIT(13), 0,            1,
      "<true|false>",            "Flush conntrack on new IP",                  "true"  },

    { "IpsetMaxElem",         "--IpsetMaxElem",         PT_INT_POS,
      offsetof(config_t, ipset_maxelem),          0,
      BIT(14), 0,            262144,
      "<int>",                   "Max entries per ipset",                      "262144"},

    { "GeoIPFile",            "--GeoIPFile",            PT_REPEAT_PATH,
      offsetof(config_t, geo_ip_files),
      offsetof(config_t, geo_ip_file_count),
      BIT(15), MAX_PATH_LEN, 0,
      "<path>",                  "GeoIP .dat file (repeatable, replaces config)",   NULL },

    { "GeoSiteFile",          "--GeoSiteFile",          PT_REPEAT_PATH,
      offsetof(config_t, geo_site_files),
      offsetof(config_t, geo_site_file_count),
      BIT(16), MAX_PATH_LEN, 0,
      "<path>",                  "GeoSite .dat file (repeatable, replaces config)", NULL },

    { "PolicyOrder",          "--PolicyOrder",          PT_POLICY_ORDER,
      offsetof(config_t, policy_order),
      offsetof(config_t, policy_order_count),
      BIT(17), 64,           0,
      "<p1,p2,...>",             "Comma-separated policy priority order",      NULL    },

    { "l7CaptureEnabled",     "--l7CaptureEnabled",     PT_BOOL,
      offsetof(config_t, l7_capture_enabled),     0,
      BIT(18), 0,            0,
      "<true|false>",            "Enable L7 (TLS/HTTP) capture via NFLOG",     "false" },

    { "l7NflogGroup",         "--l7NflogGroup",         PT_INT_POS,
      offsetof(config_t, l7_nflog_group),         0,
      BIT(19), 0,            210,
      "<int>",                   "NFLOG group number for L7 capture",          "210"   },

    { "l7EnableTLS",          "--l7EnableTLS",          PT_BOOL,
      offsetof(config_t, l7_enable_tls),          0,
      BIT(20), 0,            1,
      "<true|false>",            "Parse TLS ClientHello SNI on dport 443",     "true"  },

    { "l7EnableHTTP",         "--l7EnableHTTP",         PT_BOOL,
      offsetof(config_t, l7_enable_http),         0,
      BIT(21), 0,            1,
      "<true|false>",            "Parse HTTP Host on dport 80",                "true"  },

    { "l7WanInterface",       "--l7WanInterface",       PT_STRING,
      offsetof(config_t, l7_wan_interface),       0,
      BIT(22), MAX_INTERFACE_NAME, 0,
      "<ifname>",                "WAN interface for L7 firewall rules",        NULL    },

    { "l7ConnbytesMax",       "--l7ConnbytesMax",       PT_INT_POS,
      offsetof(config_t, l7_connbytes_max),       0,
      BIT(23), 0,            8,
      "<int>",                   "connbytes upper bound for L7 firewall rule", "8"     },

    { "l7TcpReasmEnabled",    "--l7TcpReasmEnabled",    PT_BOOL,
      offsetof(config_t, l7_tcp_reasm_enabled),   0,
      BIT(24), 0,            1,
      "<true|false>",            "Enable TCP reassembly for long ClientHello", "true"  },

    { "l7TcpReasmMaxEntries", "--l7TcpReasmMaxEntries", PT_INT_POS,
      offsetof(config_t, l7_tcp_reasm_max_entries),   0,
      BIT(25), 0,            256,
      "<int>",                   "Max concurrent reassembly entries",          "256"   },

    { "l7TcpReasmTtlSec",     "--l7TcpReasmTtlSec",     PT_INT_POS,
      offsetof(config_t, l7_tcp_reasm_ttl_sec),   0,
      BIT(26), 0,            5,
      "<seconds>",               "TTL of incomplete reassembly entries",       "5"     },
};

const int PARAMS_COUNT = sizeof(PARAMS) / sizeof(PARAMS[0]);

static int parse_int_value(const char *val, int *out, int must_be_positive) {
    char *end;
    errno = 0;
    long v = strtol(val, &end, 10);
    if (errno != 0 || *end != '\0' || end == val) return -1;
    if (must_be_positive && v <= 0) return -1;
    *out = (int)v;
    return 0;
}

int param_apply(config_t *cfg, const param_def_t *p, const char *val, int strict) {
    void *field = (char *)cfg + p->cfg_offset;

    switch (p->type) {
    case PT_BOOL:
        if (strcmp(val, "true") == 0)  { *(int *)field = 1; return 0; }
        if (strcmp(val, "false") == 0) { *(int *)field = 0; return 0; }
        if (!strict) { *(int *)field = 0; return 0; }
        return -1;

    case PT_INT:
        return parse_int_value(val, (int *)field, 0);

    case PT_INT_POS:
        return parse_int_value(val, (int *)field, 1);

    case PT_STRING:
    case PT_PATH: {
        char *buf = (char *)field;
        strncpy(buf, val, p->buf_size - 1);
        buf[p->buf_size - 1] = '\0';
        return 0;
    }

    case PT_REPEAT_PATH: {
        int *cnt = (int *)((char *)cfg + p->cfg_count_offset);
        if (*cnt >= MAX_GEO_FILES) return 0;
        char (*arr)[MAX_PATH_LEN] = (char (*)[MAX_PATH_LEN])field;
        strncpy(arr[*cnt], val, p->buf_size - 1);
        arr[*cnt][p->buf_size - 1] = '\0';
        (*cnt)++;
        return 0;
    }

    case PT_POLICY_ORDER: {
        int *cnt = (int *)((char *)cfg + p->cfg_count_offset);
        char (*arr)[64] = (char (*)[64])field;
        char tmp[4096];
        strncpy(tmp, val, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = '\0';
        char *saveptr;
        char *token = strtok_r(tmp, ",", &saveptr);
        while (token && *cnt < MAX_POLICY_ORDER) {
            char *t = trim_whitespace(token);
            if (t[0] != '\0') {
                strncpy(arr[*cnt], t, 63);
                arr[*cnt][63] = '\0';
                (*cnt)++;
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
        return 0;
    }
    }
    return -1;
}
