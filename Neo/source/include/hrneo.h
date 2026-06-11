#ifndef HRNEO_H
#define HRNEO_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define DEFAULT_CONFIG_PATH       "/opt/etc/HydraRoute/hrneo.conf"
#define DEFAULT_PID_FILE          "/var/run/hrneo.pid"
#define DEFAULT_API_PORT          79
#define IPSET_HASH_TYPE           "hash:net"
#define SOCKET_READ_BUFFER        (1024 * 1024)
#define SIGUSR1_DEBOUNCE_SEC      5
#define RCI_TIMEOUT_SEC           10
#define POLICY_API_MAX_RETRIES    5
#define POLICY_API_RETRY_DELAY    3
#define IPSET_CHUNK_SIZE          256
#define IPSET_DEFAULT_MAXELEM     262144
#define POOL_CHUNK_SIZE           (256 * 1024)

#define NFNL_SUBSYS_IPSET       6
#define IPSET_PROTOCOL          6
#define IPSET_CMD_CREATE        2
#define IPSET_CMD_FLUSH         4
#define IPSET_CMD_ADD           9
#define IPSET_CMD_TYPE         13
#define IPSET_ATTR_PROTOCOL     1
#define IPSET_ATTR_SETNAME      2
#define IPSET_ATTR_TYPENAME     3
#define IPSET_ATTR_REVISION     4
#define IPSET_ATTR_FAMILY       5
#define IPSET_ATTR_DATA         7
#define IPSET_ATTR_IP           1
#define IPSET_ATTR_IPADDR_IPV4  1
#define IPSET_ATTR_IPADDR_IPV6  2
#define IPSET_ATTR_CIDR         3
#define IPSET_ATTR_TIMEOUT      6
#define IPSET_ATTR_MAXELEM      19
#define NLA_F_NESTED            (1 << 15)
#define NLA_F_NET_BYTEORDER     (1 << 14)
#define NLM_F_EXCL              0x200
#define NLM_F_CREATE            0x400
#define IPSET_ERR_EXIST         4103
#define IPSET_ERR_HASH_FULL     4101

#define CT_NFNL_SUBSYS    1
#define CT_MSG_GET         1
#define CT_MSG_DELETE      2
#define CTA_TUPLE_ORIG     1
#define CTA_TUPLE_IP       1
#define CTA_TUPLE_PROTO    2
#define CTA_IPV4_SRC       1
#define CTA_IPV4_DST       2
#define CTA_IPV6_SRC       3
#define CTA_IPV6_DST       4
#define CTA_PROTO_NUM      1
#define CTA_PROTO_SRC_PORT 2
#define CTA_PROTO_DST_PORT 3

#define MAX_GEO_FILES       16
#define MAX_POLICY_ORDER    64
#define MAX_PATH_LEN        512
#define MAX_INTERFACE_NAME  32
#define MAX_INTERFACES      64
#define MAX_POLICY_NAME     64
#define MAX_TAG_LEN         64

#define DOMAIN_HT_BUCKETS  8192

#define MAX_CNAME_CHAIN         16

typedef struct {
    int auto_start;
    char watchlist_path[MAX_PATH_LEN];
    int clear_ipset;
    int cidr_enabled;
    char cidr_file_path[MAX_PATH_LEN];
    int ipset_enable_timeout;
    int ipset_timeout;
    char log_level[16];
    char log_file_path[MAX_PATH_LEN];
    int direct_route_enabled;
    int interface_fwmark_start;
    int interface_table_start;
    int global_routing;
    int conntrack_flush;
    int ipset_maxelem;
    char geo_ip_files[MAX_GEO_FILES][MAX_PATH_LEN];
    int geo_ip_file_count;
    char geo_site_files[MAX_GEO_FILES][MAX_PATH_LEN];
    int geo_site_file_count;
    char policy_order[MAX_POLICY_ORDER][64];
    int policy_order_count;
    int l7_capture_enabled;
    int l7_nflog_group;
    int l7_enable_tls;
    int l7_enable_http;
    int l7_connbytes_max;
    char l7_wan_interface[MAX_INTERFACE_NAME];
    int l7_tcp_reasm_enabled;
    int l7_tcp_reasm_max_entries;
    int l7_tcp_reasm_ttl_sec;
} config_t;

typedef struct {
    char ipv4[64];
    char ipv6[64];
} ipset_pair_t;

typedef struct {
    uint8_t ip[16];
    uint8_t prefix;
    uint8_t family;
} parsed_cidr_t;

typedef struct {
    uint8_t ip[16];
    uint32_t prefix;
    uint8_t ip_len;
} geoip_entry_t;

#define GEOSITE_TYPE_PLAIN  0
#define GEOSITE_TYPE_REGEX  1
#define GEOSITE_TYPE_DOMAIN 2
#define GEOSITE_TYPE_FULL   3

typedef struct {
    uint32_t type;
    char *value;
} geosite_domain_t;

typedef struct {
    char tag[MAX_TAG_LEN];
    char policy_name[MAX_POLICY_NAME];
} geosite_rule_t;

typedef struct {
    char *ipset_name;
    int match_subs;
} domain_entry_t;

typedef struct domain_node {
    char *domain;
    size_t domain_len;
    domain_entry_t entry;
    struct domain_node *next;
} domain_node_t;

typedef struct pool_chunk {
    struct pool_chunk *next;
    size_t used;
    char data[POOL_CHUNK_SIZE];
} pool_chunk_t;

typedef struct {
    domain_node_t *buckets[DOMAIN_HT_BUCKETS];
    int count;
    pool_chunk_t *pool_head;
    pool_chunk_t *pool_tail;
    char  ipset_name_cache[MAX_POLICY_ORDER][64];
    char *ipset_name_ptrs[MAX_POLICY_ORDER];
    int   ipset_name_count;
} domain_hashtable_t;

static inline uint32_t fnv1a_hash(const char *str, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint8_t)str[i];
        hash *= 16777619u;
    }
    return hash;
}

typedef struct {
    char name[MAX_INTERFACE_NAME];
    char state[16];
} interface_info_t;

typedef struct {
    char interface_name[MAX_INTERFACE_NAME];
    ipset_pair_t ipset_pair;
    int fwmark;
    int table_id;
} interface_route_t;

typedef struct {
    config_t *config;
    interface_info_t interfaces[MAX_INTERFACES];
    int interface_count;
    interface_route_t routes[MAX_INTERFACES];
    int route_count;
    int next_fwmark;
    int next_table_id;
} direct_route_manager_t;

#endif
