#ifndef ROUTING_H
#define ROUTING_H

#include "hrneo.h"

void drm_init(direct_route_manager_t *drm, config_t *config);
int drm_scan_interfaces(direct_route_manager_t *drm);
int drm_classify_target(const direct_route_manager_t *drm, const char *name);
int drm_allocate_fwmark(direct_route_manager_t *drm, const char *iface_name);
int drm_allocate_table_id(direct_route_manager_t *drm, const char *iface_name);
void drm_register_route(direct_route_manager_t *drm, const char *iface_name,
                         int fwmark, int table_id);
int drm_setup_all_routes(direct_route_manager_t *drm);
int drm_cleanup_all_routes(direct_route_manager_t *drm);
void drm_update_used_states(direct_route_manager_t *drm);
void drm_get_states(direct_route_manager_t *drm, char states[][2][32], int *count);
int drm_handle_state_changes(direct_route_manager_t *drm,
                              const char old_states[][2][32], int old_count);

int parse_watchlist_classified(const char *path, direct_route_manager_t *drm,
                                domain_hashtable_t *all_targets,
                                char policy_names[][64], int *policy_count,
                                char iface_names[][64], int *iface_count);

#endif
