#include "../include/routing.h"
#include "../include/watchlist.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

void drm_init(direct_route_manager_t *drm, config_t *config) {
    memset(drm, 0, sizeof(*drm));
    drm->config = config;
    drm->next_fwmark = config->interface_fwmark_start;
    drm->next_table_id = config->interface_table_start;
}

int drm_scan_interfaces(direct_route_manager_t *drm) {
    DIR *d = opendir("/sys/class/net");
    if (!d) return -1;

    drm->interface_count = 0;
    struct dirent *de;

    while ((de = readdir(d)) && drm->interface_count < MAX_INTERFACES) {
        if (de->d_name[0] == '.') continue;

        interface_info_t *info = &drm->interfaces[drm->interface_count];
        memset(info, 0, sizeof(*info));
        strncpy(info->name, de->d_name, MAX_INTERFACE_NAME - 1);

        char path[300];
        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", de->d_name);
        FILE *f = fopen(path, "r");
        if (f) {
            if (fgets(info->state, sizeof(info->state), f))
                info->state[strcspn(info->state, "\n")] = 0;
            fclose(f);
        } else {
            strcpy(info->state, "unknown");
        }

        drm->interface_count++;
    }

    closedir(d);
    LOG_DEBUG("Scanned %d network interfaces", drm->interface_count);
    return 0;
}

int drm_classify_target(const direct_route_manager_t *drm, const char *name) {
    for (int i = 0; i < drm->interface_count; i++) {
        if (strcmp(drm->interfaces[i].name, name) == 0)
            return 1;
    }
    return 0;
}

int drm_allocate_fwmark(direct_route_manager_t *drm, const char *iface_name) {
    for (int i = 0; i < drm->route_count; i++) {
        if (strcmp(drm->routes[i].interface_name, iface_name) == 0)
            return drm->routes[i].fwmark;
    }
    return drm->next_fwmark++;
}

int drm_allocate_table_id(direct_route_manager_t *drm, const char *iface_name) {
    for (int i = 0; i < drm->route_count; i++) {
        if (strcmp(drm->routes[i].interface_name, iface_name) == 0)
            return drm->routes[i].table_id;
    }
    return drm->next_table_id++;
}

void drm_register_route(direct_route_manager_t *drm, const char *iface_name,
                         int fwmark, int table_id) {
    if (drm->route_count >= MAX_INTERFACES) {
        LOG_WARN("Cannot register route for %s: MAX_INTERFACES (%d) reached",
                 iface_name, MAX_INTERFACES);
        return;
    }

    interface_route_t *r = &drm->routes[drm->route_count++];
    memset(r, 0, sizeof(*r));
    strncpy(r->interface_name, iface_name, MAX_INTERFACE_NAME - 1);
    snprintf(r->ipset_pair.ipv4, sizeof(r->ipset_pair.ipv4), "%s", iface_name);
    snprintf(r->ipset_pair.ipv6, sizeof(r->ipset_pair.ipv6), "%sv6", iface_name);
    r->fwmark = fwmark;
    r->table_id = table_id;

    LOG_INFO("Interface %s: assigned fwmark=0x%x, table=%d", iface_name, fwmark, table_id);
}

static int run_ip(int ipv6, const char *const tail[], char *out, size_t out_size) {
    char *argv[16];
    int i = 0;
    argv[i++] = "ip";
    if (ipv6) argv[i++] = "-6";
    for (int j = 0; tail[j] && i < 15; j++)
        argv[i++] = (char *)tail[j];
    argv[i] = NULL;
    return run_command_output("ip", argv, out, out_size);
}

static int drm_create_ip_rule(direct_route_manager_t *drm, int fwmark, int table_id, int ipv6) {
    int priority = 9 - (table_id - drm->config->interface_table_start);
    if (priority < 1) priority = 1;

    char fwmark_str[16], table_str[16], priority_str[16];
    snprintf(fwmark_str, sizeof(fwmark_str), "0x%x", fwmark);
    snprintf(table_str, sizeof(table_str), "%d", table_id);
    snprintf(priority_str, sizeof(priority_str), "%d", priority);

    char output[512];
    const char *tail[] = { "rule", "add", "priority", priority_str,
                           "fwmark", fwmark_str, "table", table_str, NULL };
    int ret = run_ip(ipv6, tail, output, sizeof(output));

    if (ret != 0) {
        if (strstr(output, "File exists")) {
            LOG_DEBUG("IP rule already exists: fwmark 0x%x table %d", fwmark, table_id);
            return 0;
        }
        LOG_WARN("Failed to create ip rule: fwmark 0x%x table %d: %s", fwmark, table_id, output);
        return -1;
    }

    LOG_INFO("Added ip rule (%s): priority %d fwmark 0x%x table %d",
             ipv6 ? "IPv6" : "IPv4", priority, fwmark, table_id);
    return 0;
}

static int drm_delete_ip_rule(int fwmark, int table_id, int ipv6) {
    char fwmark_str[16], table_str[16];
    snprintf(fwmark_str, sizeof(fwmark_str), "0x%x", fwmark);
    snprintf(table_str, sizeof(table_str), "%d", table_id);

    char output[256];
    const char *tail[] = { "rule", "del", "fwmark", fwmark_str, "table", table_str, NULL };
    run_ip(ipv6, tail, output, sizeof(output));
    return 0;
}

static int add_blackhole(int table_id, int ipv6) {
    char table_str[16];
    snprintf(table_str, sizeof(table_str), "%d", table_id);
    char output[256];
    const char *tail[] = { "route", "add", "blackhole", "default", "table", table_str, NULL };
    int ret = run_ip(ipv6, tail, output, sizeof(output));
    if (ret != 0 && strstr(output, "File exists")) return 0;
    return ret;
}

static int drm_iface_active(const char *state) {
    return strcmp(state, "up") == 0 || strcmp(state, "unknown") == 0;
}

static const char *drm_lookup_state(const direct_route_manager_t *drm, const char *iface_name) {
    for (int i = 0; i < drm->interface_count; i++) {
        if (strcmp(drm->interfaces[i].name, iface_name) == 0)
            return drm->interfaces[i].state;
    }
    return "unknown";
}

static void drm_install_route(const char *iface_name, int table_id, int active, int ipv6) {
    if (!active) {
        add_blackhole(table_id, ipv6);
        return;
    }

    char table_str[16];
    snprintf(table_str, sizeof(table_str), "%d", table_id);
    char output[512];
    const char *tail[] = { "route", "add", "default", "dev", iface_name,
                           "table", table_str, NULL };
    int ret = run_ip(ipv6, tail, output, sizeof(output));

    if (ret == 0) {
        LOG_INFO("Added route (%s): default dev %s table %d",
                 ipv6 ? "IPv6" : "IPv4", iface_name, table_id);
        return;
    }
    if (strstr(output, "File exists"))
        return;
    if (strstr(output, "can't find device")) {
        LOG_WARN("Interface %s not in kernel routing stack (%s), using blackhole",
                 iface_name, ipv6 ? "IPv6" : "IPv4");
        add_blackhole(table_id, ipv6);
        return;
    }
    LOG_WARN("Failed to add route for %s: %s", iface_name, output);
}

int drm_setup_all_routes(direct_route_manager_t *drm) {
    for (int i = 0; i < drm->route_count; i++) {
        interface_route_t *r = &drm->routes[i];
        int active = drm_iface_active(drm_lookup_state(drm, r->interface_name));
        if (!active)
            LOG_WARN("Interface %s is DOWN, using blackhole route", r->interface_name);
        for (int v6 = 0; v6 <= 1; v6++) {
            drm_create_ip_rule(drm, r->fwmark, r->table_id, v6);
            drm_install_route(r->interface_name, r->table_id, active, v6);
        }
    }
    return 0;
}

static int drm_flush_routing_table(int table_id) {
    char table_str[16];
    snprintf(table_str, sizeof(table_str), "%d", table_id);
    char output[256];

    const char *tail[] = { "route", "flush", "table", table_str, NULL };
    for (int v6 = 0; v6 <= 1; v6++)
        run_ip(v6, tail, output, sizeof(output));

    LOG_INFO("Flushed routing table %d", table_id);
    return 0;
}

static int drm_update_route_on_state_change(const char *iface_name, int table_id,
                                            const char *new_state) {
    drm_flush_routing_table(table_id);

    int active = drm_iface_active(new_state);
    for (int v6 = 0; v6 <= 1; v6++)
        drm_install_route(iface_name, table_id, active, v6);

    if (active)
        LOG_INFO("Normal routing restored for interface %s (table %d)", iface_name, table_id);
    else
        LOG_INFO("Blackhole route activated for interface %s (table %d)", iface_name, table_id);

    return 0;
}

void drm_update_used_states(direct_route_manager_t *drm) {
    for (int i = 0; i < drm->route_count; i++) {
        const char *name = drm->routes[i].interface_name;
        char path[128];
        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", name);
        FILE *f = fopen(path, "r");
        if (f) {
            char state[16];
            if (fgets(state, sizeof(state), f)) {
                state[strcspn(state, "\n")] = 0;
                for (int j = 0; j < drm->interface_count; j++) {
                    if (strcmp(drm->interfaces[j].name, name) == 0) {
                        strncpy(drm->interfaces[j].state, state, 15);
                        break;
                    }
                }
            }
            fclose(f);
        }
    }
}

void drm_get_states(direct_route_manager_t *drm, char states[][2][32], int *count) {
    *count = 0;
    for (int i = 0; i < drm->route_count; i++) {
        strncpy(states[*count][0], drm->routes[i].interface_name, 31);
        states[*count][0][31] = 0;
        states[*count][1][0] = 0;
        for (int j = 0; j < drm->interface_count; j++) {
            if (strcmp(drm->interfaces[j].name, drm->routes[i].interface_name) == 0) {
                strncpy(states[*count][1], drm->interfaces[j].state, 31);
                states[*count][1][31] = 0;
                break;
            }
        }
        (*count)++;
    }
}

int drm_handle_state_changes(direct_route_manager_t *drm,
                              const char old_states[][2][32], int old_count) {
    for (int i = 0; i < drm->route_count; i++) {
        const char *name = drm->routes[i].interface_name;

        const char *old_state = NULL;
        for (int j = 0; j < old_count; j++) {
            if (strcmp(old_states[j][0], name) == 0) {
                old_state = old_states[j][1];
                break;
            }
        }

        const char *new_state = NULL;
        for (int j = 0; j < drm->interface_count; j++) {
            if (strcmp(drm->interfaces[j].name, name) == 0) {
                new_state = drm->interfaces[j].state;
                break;
            }
        }

        if (!new_state) {
            LOG_WARN("Interface %s disappeared", name);
            continue;
        }

        if (old_state && strcmp(old_state, new_state) != 0) {
            LOG_INFO("Interface %s state changed: %s -> %s", name, old_state, new_state);
            drm_update_route_on_state_change(name, drm->routes[i].table_id, new_state);
        }
    }
    return 0;
}

int drm_cleanup_all_routes(direct_route_manager_t *drm) {
    for (int i = 0; i < drm->route_count; i++) {
        interface_route_t *r = &drm->routes[i];
        for (int v6 = 0; v6 <= 1; v6++)
            drm_delete_ip_rule(r->fwmark, r->table_id, v6);
        drm_flush_routing_table(r->table_id);
    }
    return 0;
}

typedef struct {
    direct_route_manager_t *drm;
    domain_hashtable_t *all_targets;
    char (*policy_names)[64];
    int *policy_count;
    char (*iface_names)[64];
    int *iface_count;
} classify_ctx_t;

static int classify_on_target(const char *target, void *user) {
    classify_ctx_t *cx = (classify_ctx_t *)user;
    int is_interface = drm_classify_target(cx->drm, target);
    char (*list)[64] = is_interface ? cx->iface_names : cx->policy_names;
    int *count = is_interface ? cx->iface_count : cx->policy_count;
    int max = is_interface ? MAX_INTERFACES : MAX_POLICY_ORDER;
    for (int i = 0; i < *count; i++) {
        if (strcmp(list[i], target) == 0) return 1;
    }
    if (*count < max) {
        strncpy(list[*count], target, 63);
        list[*count][63] = 0;
        (*count)++;
    }
    return 1;
}

static void classify_on_domain(const char *target, const char *domain,
                                size_t domain_len, void *user) {
    classify_ctx_t *cx = (classify_ctx_t *)user;
    ht_insert(cx->all_targets, domain, domain_len, target, 1);
}

int parse_watchlist_classified(const char *path, direct_route_manager_t *drm,
                                domain_hashtable_t *all_targets,
                                char policy_names[][64], int *policy_count,
                                char iface_names[][64], int *iface_count) {
    *policy_count = 0;
    *iface_count = 0;

    classify_ctx_t ctx = {
        .drm = drm,
        .all_targets = all_targets,
        .policy_names = policy_names,
        .policy_count = policy_count,
        .iface_names = iface_names,
        .iface_count = iface_count,
    };

    int rc = parse_watchlist_lines(path, classify_on_target, classify_on_domain, &ctx);
    if (rc != 0) return rc;

    LOG_INFO("domain.conf: %d policies, %d interfaces", *policy_count, *iface_count);
    return 0;
}
