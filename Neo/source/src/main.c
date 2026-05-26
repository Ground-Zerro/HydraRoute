#include "../include/hrneo.h"
#include "../include/config.h"
#include "../include/args.h"
#include "../include/log.h"
#include "../include/util.h"
#include "../include/watchlist.h"
#include "../include/ipset_nl.h"
#include "../include/dns.h"
#include "../include/packet_capture.h"
#include "../include/iptables.h"
#include "../include/signal_handler.h"
#include "../include/rci.h"
#include "../include/conntrack.h"
#include "../include/geodat.h"
#include "../include/routing.h"
#include "../include/nfq_capture.h"
#include "../include/l7_dispatch.h"
#include "../include/l7_firewall.h"
#include "../include/tcp_reasm.h"
#include <sys/timerfd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <errno.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static config_t g_config;
static domain_hashtable_t *g_all_targets;
static ipset_manager_t g_ipset_mgr;
static volatile int g_shutdown;
static direct_route_manager_t g_drm;
static int g_drm_active;
static unified_target_t g_all_sorted[MAX_POLICY_ORDER + MAX_INTERFACES];
static int g_all_sorted_count;
static conntrack_mgr_t g_conntrack = { .fd = -1 };
static rci_client_t g_rci;
static nfq_capture_t g_nfq;
static int g_l7_active;
static char g_l7_wan[MAX_INTERFACE_NAME];
static tcp_reasm_t g_reasm;
static int g_reasm_active;

static int create_pid_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (f) {
        char buf[32];
        if (fgets(buf, sizeof(buf), f)) {
            int old_pid = atoi(buf);
            if (old_pid > 0) {
                char proc_path[64];
                snprintf(proc_path, sizeof(proc_path), "/proc/%d", old_pid);
                struct stat st;
                if (stat(proc_path, &st) == 0) {
                    fclose(f);
                    LOG_ERROR("Already running (PID %d)", old_pid);
                    return -1;
                }
                LOG_WARN("Removing stale PID file (PID %d not found)", old_pid);
            }
        }
        fclose(f);
        unlink(path);
    }

    f = fopen(path, "w");
    if (!f) {
        LOG_ERROR("Cannot create PID file: %s: %s", path, strerror(errno));
        return -1;
    }
    fprintf(f, "%d\n", getpid());
    fclose(f);
    return 0;
}

static void remove_pid_file(const char *path) {
    if (unlink(path) != 0 && errno != ENOENT) {
        LOG_WARN("PID file remove error: %s", strerror(errno));
    }
}

static int initialize_ipsets(ipset_manager_t *mgr, const ipset_pair_t *pairs, int count,
                             int clear, int enable_timeout, int timeout, uint32_t maxelem) {
    for (int i = 0; i < count; i++) {
        uint32_t to = (enable_timeout && timeout > 0) ? (uint32_t)timeout : 0;

        ipset_create(mgr, pairs[i].ipv4, IPSET_HASH_TYPE, AF_INET, to, maxelem);
        ipset_create(mgr, pairs[i].ipv6, IPSET_HASH_TYPE, AF_INET6, to, maxelem);

        if (enable_timeout && timeout > 0) {
            ipset_cache_timeout_for_set(mgr, pairs[i].ipv4, 1, (uint32_t)timeout);
            ipset_cache_timeout_for_set(mgr, pairs[i].ipv6, 1, (uint32_t)timeout);
        }

        if (clear) {
            ipset_flush(mgr, pairs[i].ipv4);
            ipset_flush(mgr, pairs[i].ipv6);
        }
    }
    return 0;
}

static void format_ipv4(const uint8_t *ip, char *buf, int buf_size) {
    snprintf(buf, buf_size, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

static void format_ipv6(const uint8_t *ip, char *buf, int buf_size) {
    char tmp[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, tmp, sizeof(tmp));
    snprintf(buf, buf_size, "%s", tmp);
}

static void process_hostname_event(const char *domain,
                                   const cname_entry_t *cnames, int cname_count,
                                   const parsed_cidr_t *ipv4_batch, int ipv4_count,
                                   const parsed_cidr_t *ipv6_batch, int ipv6_count,
                                   const char *source_tag) {
    const char *matched_domain = NULL;
    const char *ipset_name = match_domain_with_cname(
        g_all_targets,
        (const char (*)[64])g_config.policy_order, g_config.policy_order_count,
        domain, cnames, cname_count, &matched_domain);

    if (!ipset_name) return;

    if (matched_domain && matched_domain != domain)
        LOG_MATCH("[%s] %s via %s -> %s", source_tag, domain, matched_domain, ipset_name);
    else
        LOG_MATCH("[%s] %s -> %s", source_tag, domain, ipset_name);

    parsed_cidr_t all_new[64];
    int all_new_count = 0;

    if (ipv4_count > 0) {
        int new_count = 0;
        int new_indices[32];
        ipset_add_batch(&g_ipset_mgr, ipset_name,
                        ipv4_batch, ipv4_count, 1, &new_count, new_indices);
        for (int k = 0; k < new_count; k++) {
            char ip_str[INET_ADDRSTRLEN];
            format_ipv4(ipv4_batch[new_indices[k]].ip, ip_str, sizeof(ip_str));
            LOG_PROCESSED("[%s] %s -> %s [%s]", source_tag, domain, ip_str, ipset_name);
            if (all_new_count < 64)
                all_new[all_new_count++] = ipv4_batch[new_indices[k]];
        }
    }

    if (ipv6_count > 0) {
        char ipv6_set[64];
        snprintf(ipv6_set, sizeof(ipv6_set), "%.60sv6", ipset_name);
        int new_count = 0;
        int new_indices[32];
        ipset_add_batch(&g_ipset_mgr, ipv6_set,
                        ipv6_batch, ipv6_count, 1, &new_count, new_indices);
        for (int k = 0; k < new_count; k++) {
            char ip_str[INET6_ADDRSTRLEN];
            format_ipv6(ipv6_batch[new_indices[k]].ip, ip_str, sizeof(ip_str));
            LOG_PROCESSED("[%s] %s -> %s [%s]", source_tag, domain, ip_str, ipv6_set);
            if (all_new_count < 64)
                all_new[all_new_count++] = ipv6_batch[new_indices[k]];
        }
    }

    if (g_config.conntrack_flush && all_new_count > 0) {
        conntrack_flush_for_ips(&g_conntrack, all_new, all_new_count);
    }
}

void process_hostname_event_l7(const char *host, int proto,
                               const uint8_t *daddr, int family) {
    parsed_cidr_t entry;
    memset(&entry, 0, sizeof(entry));

    if (family == AF_INET) {
        memcpy(entry.ip, daddr, 4);
        entry.prefix = 32;
        entry.family = AF_INET;
        const char *tag = (proto == L7_TLS) ? "TLS-SNI" : "HTTP-Host";
        process_hostname_event(host, NULL, 0, &entry, 1, NULL, 0, tag);
    } else {
        memcpy(entry.ip, daddr, 16);
        entry.prefix = 128;
        entry.family = AF_INET6;
        const char *tag = (proto == L7_TLS) ? "TLS-SNI" : "HTTP-Host";
        process_hostname_event(host, NULL, 0, NULL, 0, &entry, 1, tag);
    }
}

static void process_dns_packet(const uint8_t *pkt, int pkt_len, void *user_data) {
    (void)user_data;
    int dns_len;
    const uint8_t *dns = extract_dns_payload(pkt, pkt_len, &dns_len);
    if (!dns) return;

    static dns_result_t result;
    if (dns_parse_response(dns, dns_len, &result) != 0) return;

    char processed[64][256];
    int processed_count = 0;

    static cname_entry_t cnames[DNS_MAX_CNAMES];
    int cname_total = result.cname_count;
    if (cname_total > DNS_MAX_CNAMES) cname_total = DNS_MAX_CNAMES;
    for (int c = 0; c < cname_total; c++) {
        strncpy(cnames[c].from, result.cnames[c].source, 255);
        cnames[c].from[255] = '\0';
        strncpy(cnames[c].to, result.cnames[c].target, 255);
        cnames[c].to[255] = '\0';
    }

    for (int i = 0; i < result.answer_count; i++) {
        const char *domain = result.answers[i].domain;

        int already = 0;
        for (int j = 0; j < processed_count; j++) {
            if (strcmp(processed[j], domain) == 0) { already = 1; break; }
        }
        if (already) continue;

        if (processed_count < 64) {
            strncpy(processed[processed_count], domain, 255);
            processed[processed_count][255] = '\0';
            processed_count++;
        }

        parsed_cidr_t ipv4_batch[32], ipv6_batch[32];
        int ipv4_count = 0, ipv6_count = 0;

        for (int j = 0; j < result.answer_count; j++) {
            if (strcmp(result.answers[j].domain, domain) != 0) continue;
            if (result.answers[j].family == AF_INET && ipv4_count < 32) {
                memset(&ipv4_batch[ipv4_count], 0, sizeof(parsed_cidr_t));
                memcpy(ipv4_batch[ipv4_count].ip, result.answers[j].ip, 4);
                ipv4_batch[ipv4_count].prefix = 32;
                ipv4_batch[ipv4_count].family = AF_INET;
                ipv4_count++;
            } else if (result.answers[j].family == AF_INET6 && ipv6_count < 32) {
                memset(&ipv6_batch[ipv6_count], 0, sizeof(parsed_cidr_t));
                memcpy(ipv6_batch[ipv6_count].ip, result.answers[j].ip, 16);
                ipv6_batch[ipv6_count].prefix = 128;
                ipv6_batch[ipv6_count].family = AF_INET6;
                ipv6_count++;
            }
        }

        process_hostname_event(domain, cnames, cname_total,
                               ipv4_batch, ipv4_count,
                               ipv6_batch, ipv6_count,
                               "DNS");
    }
}

static void perform_update(void) {
    if (g_drm_active) {
        char old_states[MAX_INTERFACES][2][32];
        int old_count;
        drm_get_states(&g_drm, old_states, &old_count);
        drm_update_used_states(&g_drm);
        drm_handle_state_changes(&g_drm, (const char (*)[2][32])old_states, old_count);
    }
    apply_unified_connmark_rules(&g_rci, g_all_sorted, g_all_sorted_count, g_config.global_routing);
    if (g_config.l7_capture_enabled && g_l7_active && g_l7_wan[0])
        l7_firewall_install(&g_config, g_l7_wan);
    LOG_INFO("iptables updated");
}

static void add_unique_name(char names[][64], int *count, const char *name, int max) {
    for (int i = 0; i < *count; i++) {
        if (strcmp(names[i], name) == 0) return;
    }
    if (*count < max) {
        strncpy(names[*count], name, 63);
        names[*count][63] = '\0';
        (*count)++;
    }
}

int main(int argc, char *argv[]) {
    cli_args_t args;
    int ar = args_parse(argc, argv, &args);
    if (ar == 3) return config_generate(args.genconfig_target);
    if (ar > 0) return 0;
    if (ar < 0) return 1;

    {
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGUSR1);
        sigprocmask(SIG_BLOCK, &mask, NULL);
    }

    const char *cfg_path = args.config_path[0] ? args.config_path : DEFAULT_CONFIG_PATH;
    int cfg_err = config_read(cfg_path, &g_config);
    if (cfg_err != 0 && args.config_path[0]) {
        return 1;
    }

    args_apply(&args, &g_config);

    if (!g_config.auto_start) return 0;

    log_setup(&g_config);
    LOG_INFO("HRNeo v%s starting", VERSION);

    if (create_pid_file(DEFAULT_PID_FILE) != 0) {
        log_close();
        return 1;
    }

    g_all_targets = ht_create();
    if (!g_all_targets) {
        LOG_ERROR("Failed to create hashtable");
        goto cleanup;
    }

    char policy_names[MAX_POLICY_ORDER][64];
    int policy_count = 0;
    char iface_names[MAX_INTERFACES][64];
    int iface_count = 0;

    g_drm_active = g_config.direct_route_enabled;

    if (g_drm_active) {
        drm_init(&g_drm, &g_config);
        drm_scan_interfaces(&g_drm);

        if (parse_watchlist_classified(g_config.watchlist_path, &g_drm,
                                        g_all_targets,
                                        policy_names, &policy_count,
                                        iface_names, &iface_count) != 0) {
            LOG_ERROR("Failed to parse watchlist (classified)");
            goto cleanup;
        }

        for (int i = 0; i < iface_count; i++) {
            int fwmark = drm_allocate_fwmark(&g_drm, iface_names[i]);
            int table_id = drm_allocate_table_id(&g_drm, iface_names[i]);
            drm_register_route(&g_drm, iface_names[i], fwmark, table_id);
        }
    } else {
        if (parse_watchlist(g_config.watchlist_path, g_all_targets) != 0) {
            LOG_ERROR("Failed to parse watchlist");
            goto cleanup;
        }
        policy_count = get_unique_names(g_all_targets, policy_names, MAX_POLICY_ORDER);
    }

    if (g_config.cidr_enabled && g_config.cidr_file_path[0] != '\0') {
        int pc_before = policy_count;
        char cidr_names[MAX_POLICY_ORDER][64];
        int cidr_count = parse_cidr_policy_headers(g_config.cidr_file_path, cidr_names, MAX_POLICY_ORDER);
        for (int i = 0; i < cidr_count; i++) {
            if (g_drm_active && drm_classify_target(&g_drm, cidr_names[i]))
                continue;
            add_unique_name(policy_names, &policy_count, cidr_names[i], MAX_POLICY_ORDER);
        }
        for (int i = pc_before; i < policy_count; i++)
            LOG_INFO("CIDR: added policy '%s'", policy_names[i]);
    }

    if (g_config.geo_site_file_count > 0) {
        int pc_before = policy_count;
        geosite_rule_t gs_rules[256];
        int gs_count = parse_geosite_rules(g_config.watchlist_path, gs_rules, 256);
        for (int i = 0; i < gs_count; i++) {
            if (g_drm_active && drm_classify_target(&g_drm, gs_rules[i].policy_name))
                continue;
            add_unique_name(policy_names, &policy_count, gs_rules[i].policy_name, MAX_POLICY_ORDER);
        }
        for (int i = pc_before; i < policy_count; i++)
            LOG_INFO("GeoSite: added policy '%s'", policy_names[i]);
    }

    sort_policies(policy_names, policy_count,
                  (const char (*)[64])g_config.policy_order, g_config.policy_order_count);

    {
        char all_names[MAX_POLICY_ORDER + MAX_INTERFACES][64];
        int all_count = 0;
        for (int i = 0; i < policy_count; i++) {
            strncpy(all_names[all_count], policy_names[i], 63);
            all_names[all_count][63] = 0;
            all_count++;
        }
        for (int i = 0; i < iface_count; i++) {
            strncpy(all_names[all_count], iface_names[i], 63);
            all_names[all_count][63] = 0;
            all_count++;
        }
        sort_policies(all_names, all_count,
                      (const char (*)[64])g_config.policy_order, g_config.policy_order_count);

        g_all_sorted_count = all_count;
        for (int i = 0; i < all_count; i++) {
            strncpy(g_all_sorted[i].pair.ipv4, all_names[i], 63);
            g_all_sorted[i].pair.ipv4[63] = 0;
            snprintf(g_all_sorted[i].pair.ipv6, sizeof(g_all_sorted[i].pair.ipv6),
                     "%.60sv6", all_names[i]);
            g_all_sorted[i].is_interface = g_drm_active && drm_classify_target(&g_drm, all_names[i]);
            g_all_sorted[i].fwmark = 0;
            if (g_all_sorted[i].is_interface) {
                for (int r = 0; r < g_drm.route_count; r++) {
                    if (strcmp(g_drm.routes[r].interface_name, all_names[i]) == 0) {
                        g_all_sorted[i].fwmark = g_drm.routes[r].fwmark;
                        break;
                    }
                }
            }
        }
    }

    LOG_INFO("Target order (%d):", g_all_sorted_count);
    for (int i = 0; i < g_all_sorted_count; i++) {
        if (g_all_sorted[i].is_interface)
            LOG_INFO("  [%d] %s (interface, fwmark=0x%x)", i,
                     g_all_sorted[i].pair.ipv4, g_all_sorted[i].fwmark);
        else
            LOG_INFO("  [%d] %s (policy)", i, g_all_sorted[i].pair.ipv4);
    }

    if (rci_client_init(&g_rci) != 0) {
        goto cleanup;
    }

    rci_create_policies(&g_rci, (const char (*)[64])policy_names, policy_count);

    if (ipset_manager_init(&g_ipset_mgr) != 0) {
        LOG_ERROR("Failed to init ipset manager");
        goto cleanup_rci;
    }

    {
        ipset_pair_t init_pairs[MAX_POLICY_ORDER + MAX_INTERFACES];
        for (int i = 0; i < g_all_sorted_count; i++)
            init_pairs[i] = g_all_sorted[i].pair;
        initialize_ipsets(&g_ipset_mgr, init_pairs, g_all_sorted_count,
                          g_config.clear_ipset, g_config.ipset_enable_timeout, g_config.ipset_timeout,
                          (uint32_t)g_config.ipset_maxelem);
    }

    if (g_config.cidr_enabled && g_config.cidr_file_path[0] != '\0') {
        ipset_pair_t all_pairs[MAX_POLICY_ORDER + MAX_INTERFACES];
        for (int i = 0; i < g_all_sorted_count; i++)
            all_pairs[i] = g_all_sorted[i].pair;

        add_cidr_to_ipsets(&g_ipset_mgr, g_config.cidr_file_path,
                           all_pairs, g_all_sorted_count,
                           g_config.ipset_enable_timeout, g_config.ipset_timeout,
                           (const char (*)[512])g_config.geo_ip_files, g_config.geo_ip_file_count,
                           (uint32_t)g_config.ipset_maxelem);
    }

    if (g_config.geo_site_file_count > 0) {
        geosite_rule_t geosite_rules[256];
        int geosite_rule_count = parse_geosite_rules(g_config.watchlist_path,
                                                     geosite_rules, 256);
        if (geosite_rule_count > 0) {
            build_geosite_domain_map(
                (const char (*)[512])g_config.geo_site_files, g_config.geo_site_file_count,
                geosite_rules, geosite_rule_count,
                g_all_targets);
        }
    }

    if (g_drm_active) {
        drm_setup_all_routes(&g_drm);
    }

    apply_unified_connmark_rules(&g_rci, g_all_sorted, g_all_sorted_count, g_config.global_routing);

    if (g_config.conntrack_flush) {
        if (conntrack_mgr_init(&g_conntrack) != 0) {
            LOG_WARN("conntrack manager init failed; conntrack flush disabled");
            g_config.conntrack_flush = 0;
        }
    }

    pkt_capture_t cap;
    if (pkt_capture_init(&cap, process_dns_packet, NULL) != 0) {
        LOG_ERROR("Failed to init packet capture");
        goto cleanup_conntrack;
    }

    if (g_config.l7_capture_enabled) {
        if (l7_firewall_resolve_wan(&g_config, g_l7_wan, sizeof(g_l7_wan)) != 0) {
            LOG_WARN("L7 capture: WAN interface unknown; disabling L7");
        } else {
            LOG_INFO("L7 WAN interface: %s", g_l7_wan);
            l7_firewall_load_kmod("xt_connbytes");
            l7_dispatch_set_enable(g_config.l7_enable_tls, g_config.l7_enable_http);

            if (g_config.l7_tcp_reasm_enabled) {
                if (tcp_reasm_init(&g_reasm,
                                   g_config.l7_tcp_reasm_max_entries,
                                   g_config.l7_tcp_reasm_ttl_sec) == 0) {
                    l7_dispatch_set_reasm(&g_reasm);
                    g_reasm_active = 1;
                    LOG_INFO("TCP reassembly enabled (max=%d, ttl=%ds)",
                             g_config.l7_tcp_reasm_max_entries,
                             g_config.l7_tcp_reasm_ttl_sec);
                } else {
                    LOG_WARN("TCP reassembly init failed; long ClientHello won't be assembled");
                }
            } else {
                LOG_INFO("TCP reassembly disabled (l7TcpReasmEnabled=false)");
            }

            if (nfq_capture_init(&g_nfq, (uint16_t)g_config.l7_queue_num,
                                 l7_dispatch_packet, NULL) == 0) {
                if (l7_firewall_install(&g_config, g_l7_wan) == 0) {
                    g_l7_active = 1;
                    LOG_INFO("L7 capture enabled, NFQ #%d (TLS=%d HTTP=%d)",
                             g_config.l7_queue_num,
                             g_config.l7_enable_tls, g_config.l7_enable_http);
                } else {
                    LOG_WARN("L7 firewall install failed; closing NFQ");
                    nfq_capture_close(&g_nfq);
                }
            } else {
                LOG_WARN("L7 capture init failed; continuing with DNS only");
            }
        }
    } else {
        LOG_INFO("L7 capture disabled (l7CaptureEnabled=false); DNS-only mode");
    }

    signal_mgr_t signals;
    if (signal_mgr_init(&signals) != 0) {
        LOG_ERROR("Failed to init signal manager");
        goto cleanup_capture;
    }

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        LOG_ERROR("epoll_create failed");
        goto cleanup_signals;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = cap.fd4;
    epoll_ctl(epfd, EPOLL_CTL_ADD, cap.fd4, &ev);
    ev.data.fd = cap.fd6;
    epoll_ctl(epfd, EPOLL_CTL_ADD, cap.fd6, &ev);

    ev.data.fd = signals.sig_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, signals.sig_fd, &ev);

    ev.data.fd = signals.timer_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, signals.timer_fd, &ev);

    int nfq_fd = -1;
    if (g_l7_active) {
        nfq_fd = nfq_capture_fd(&g_nfq);
        ev.data.fd = nfq_fd;
        epoll_ctl(epfd, EPOLL_CTL_ADD, nfq_fd, &ev);
    }

    int reasm_gc_fd = -1;
    if (g_l7_active && g_reasm_active) {
        reasm_gc_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        if (reasm_gc_fd >= 0) {
            struct itimerspec its = {
                .it_interval = {.tv_sec = 1, .tv_nsec = 0},
                .it_value    = {.tv_sec = 1, .tv_nsec = 0},
            };
            timerfd_settime(reasm_gc_fd, 0, &its, NULL);
            ev.data.fd = reasm_gc_fd;
            epoll_ctl(epfd, EPOLL_CTL_ADD, reasm_gc_fd, &ev);
        }
    }

    LOG_INFO("Packet capture started, waiting for DNS responses...");

    int timer_active = 0;
    int pending_update = 0;

    struct epoll_event events[8];
    while (!g_shutdown) {
        int n = epoll_wait(epfd, events, 8, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("epoll_wait: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == cap.fd4 || events[i].data.fd == cap.fd6) {
                pkt_capture_process(&cap, events[i].data.fd);
            } else if (g_l7_active && events[i].data.fd == nfq_fd) {
                nfq_capture_process(&g_nfq);
            } else if (reasm_gc_fd >= 0 && events[i].data.fd == reasm_gc_fd) {
                uint64_t exp;
                ssize_t r = read(reasm_gc_fd, &exp, sizeof(exp));
                (void)r;
                tcp_reasm_gc(&g_reasm);
            } else if (events[i].data.fd == signals.sig_fd) {
                struct signalfd_siginfo si;
                ssize_t s = read(signals.sig_fd, &si, sizeof(si));
                if (s == sizeof(si)) {
                    if (si.ssi_signo == SIGINT || si.ssi_signo == SIGTERM) {
                        LOG_INFO("Received signal %d, shutting down...", si.ssi_signo);
                        g_shutdown = 1;
                    } else if (si.ssi_signo == SIGUSR1) {
                        if (!timer_active) {
                            LOG_INFO("SIGUSR1 received, updating iptables rules...");
                            timer_active = 1;
                            pending_update = 0;
                            perform_update();
                            signal_mgr_arm_timer(&signals, 5);
                        } else {
                            LOG_INFO("SIGUSR1 received during timer, deferring update...");
                            pending_update = 1;
                        }
                    }
                }
            } else if (events[i].data.fd == signals.timer_fd) {
                signal_mgr_read_timer(&signals);
                int do_update = pending_update;
                timer_active = 0;
                pending_update = 0;
                if (do_update) {
                    LOG_INFO("SIGUSR1 timer expired, updating iptables rules...");
                    perform_update();
                }
            }
        }
    }

    if (reasm_gc_fd >= 0) close(reasm_gc_fd);
    close(epfd);

cleanup_signals:
    signal_mgr_close(&signals);

cleanup_capture:
    if (g_l7_active) {
        l7_firewall_remove(&g_config, g_l7_wan);
        nfq_capture_close(&g_nfq);
        g_l7_active = 0;
    }
    if (g_reasm_active) {
        l7_dispatch_set_reasm(NULL);
        tcp_reasm_close(&g_reasm);
        g_reasm_active = 0;
    }
    pkt_capture_close(&cap);

cleanup_conntrack:
    conntrack_mgr_close(&g_conntrack);

    if (g_drm_active) {
        drm_cleanup_all_routes(&g_drm);
    }
    {
        ipset_pair_t cleanup_pairs[MAX_POLICY_ORDER + MAX_INTERFACES];
        for (int i = 0; i < g_all_sorted_count; i++)
            cleanup_pairs[i] = g_all_sorted[i].pair;
        cleanup_connmark_rules(cleanup_pairs, g_all_sorted_count);
    }
    ipset_manager_close(&g_ipset_mgr);

cleanup_rci:
    rci_client_close(&g_rci);

cleanup:
    if (g_all_targets) ht_destroy(g_all_targets);
    remove_pid_file(DEFAULT_PID_FILE);
    LOG_INFO("HRNeo stopped");
    log_close();
    return 0;
}
