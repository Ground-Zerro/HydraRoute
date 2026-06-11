#ifndef L7_FIREWALL_H
#define L7_FIREWALL_H

#include "hrneo.h"
#include <stddef.h>

int l7_firewall_resolve_wan(const config_t *cfg, char *out, size_t out_size);
int l7_firewall_load_kmod(const char *module_name);
int l7_firewall_load_nflog_modules(void);
int l7_firewall_install(const config_t *cfg, const char *wan_iface);
int l7_firewall_remove(const config_t *cfg, const char *wan_iface);

#endif
