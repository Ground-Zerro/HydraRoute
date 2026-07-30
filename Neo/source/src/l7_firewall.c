#include "../include/l7_firewall.h"
#include "../include/iptables.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

#ifndef __NR_init_module
#error "init_module syscall not available in this libc"
#endif

static int detect_wan_from_proc(char *out, size_t out_size) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return -1;

    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return -1; }

    while (fgets(line, sizeof(line), f)) {
        char iface[64];
        char dest[16];
        if (sscanf(line, "%63s %15s", iface, dest) != 2) continue;
        if (strcmp(dest, "00000000") == 0) {
            strncpy(out, iface, out_size - 1);
            out[out_size - 1] = '\0';
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return -1;
}

static int iface_exists(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s", name);
    struct stat st;
    return stat(path, &st) == 0;
}

int l7_firewall_resolve_wan(const config_t *cfg, char *out, size_t out_size) {
    if (cfg->l7_wan_interface[0] != '\0') {
        if (iface_exists(cfg->l7_wan_interface)) {
            strncpy(out, cfg->l7_wan_interface, out_size - 1);
            out[out_size - 1] = '\0';
            return 0;
        }
        LOG_WARN("L7 WAN '%s' from config does not exist; falling back to auto-detect",
                 cfg->l7_wan_interface);
    }
    return detect_wan_from_proc(out, out_size);
}

static int module_already_loaded(const char *name) {
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return 0;
    char line[256];
    size_t name_len = strlen(name);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, name, name_len) == 0 &&
            (line[name_len] == ' ' || line[name_len] == '\t')) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

static int find_kmod_path(const char *name, char *out, size_t out_size) {
    struct utsname un;
    if (uname(&un) < 0) return -1;

    snprintf(out, out_size, "/lib/modules/%s/%s.ko", un.release, name);
    struct stat st;
    if (stat(out, &st) == 0) return 0;
    return -1;
}

int l7_firewall_load_kmod(const char *module_name) {
    if (module_already_loaded(module_name)) {
        LOG_DEBUG("kmod %s already loaded", module_name);
        return 0;
    }

    char path[512];
    if (find_kmod_path(module_name, path, sizeof(path)) != 0) {
        LOG_WARN("kmod %s: file not found under /lib/modules", module_name);
        return -1;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_WARN("kmod %s: open %s: %s", module_name, path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        close(fd);
        LOG_WARN("kmod %s: fstat failed", module_name);
        return -1;
    }

    size_t sz = (size_t)st.st_size;
    void *buf = malloc(sz);
    if (!buf) { close(fd); return -1; }

    size_t total = 0;
    while (total < sz) {
        ssize_t n = read(fd, (char *)buf + total, sz - total);
        if (n <= 0) { free(buf); close(fd); return -1; }
        total += (size_t)n;
    }
    close(fd);

    long rc = syscall(__NR_init_module, buf, (unsigned long)sz, "");
    int saved_errno = errno;
    free(buf);

    if (rc < 0 && saved_errno != EEXIST) {
        LOG_WARN("kmod %s: init_module failed: %s", module_name, strerror(saved_errno));
        return -1;
    }
    LOG_INFO("kmod %s loaded", module_name);
    return 0;
}

int l7_firewall_load_nflog_modules(void) {
    if (l7_firewall_load_kmod("nfnetlink_log") != 0) return -1;
    if (l7_firewall_load_kmod("xt_NFLOG") != 0) return -1;
    return 0;
}

static const char *const L7_CMDS[]   = {"iptables", "ip6tables"};
static const char *const L7_CHAINS[] = {"FORWARD", "OUTPUT"};

typedef struct {
    int dport;
    int connbytes_max;
} l7_rule_spec_t;

static int l7_nflog_group(const config_t *cfg) {
    return cfg->l7_nflog_group > 0 ? cfg->l7_nflog_group : 210;
}

static void l7_rule_specs(const config_t *cfg, l7_rule_spec_t specs[2]) {
    int max443 = cfg->l7_connbytes_max > 0 ? cfg->l7_connbytes_max : 8;
    specs[0].dport = 443;
    specs[0].connbytes_max = max443;
    specs[1].dport = 80;
    specs[1].connbytes_max = max443 < 4 ? max443 : 4;
}

static int dump_has_rule(const char *dump, const char *chain, const char *wan,
                         const char *proto, int dport, int group) {
    char c_tok[40], o_tok[MAX_INTERFACE_NAME + 8], p_tok[16], d_tok[24], g_tok[32];
    snprintf(c_tok, sizeof(c_tok), "-A %s ", chain);
    snprintf(o_tok, sizeof(o_tok), "-o %s ", wan);
    snprintf(p_tok, sizeof(p_tok), "-p %s ", proto);
    snprintf(d_tok, sizeof(d_tok), "--dport %d ", dport);
    snprintf(g_tok, sizeof(g_tok), "--nflog-group %d", group);

    const char *line = dump;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        if (line_find(line, len, c_tok) == line &&
            line_find(line, len, o_tok) && line_find(line, len, p_tok) &&
            line_find(line, len, d_tok) && line_find(line, len, g_tok))
            return 1;
        line = nl ? nl + 1 : NULL;
    }
    return 0;
}

int l7_firewall_emit_rules(const config_t *cfg, const char *wan,
                           const char *dump, char *out, size_t out_size) {
    if (!wan || wan[0] == '\0') return 0;
    l7_rule_spec_t specs[2];
    l7_rule_specs(cfg, specs);
    int group = l7_nflog_group(cfg);
    size_t off = 0;

    for (int ch = 0; ch < 2; ch++) {
        for (int p = 0; p < 2; p++) {
            if (dump_has_rule(dump, L7_CHAINS[ch], wan, "tcp", specs[p].dport, group))
                continue;
            int n = snprintf(out + off, out_size - off,
                "-A %s -o %s -p tcp --dport %d --tcp-flags SYN,ACK ACK "
                "-m connbytes --connbytes-dir original --connbytes-mode packets "
                "--connbytes 2:%d -m length --length 60: "
                "-j NFLOG --nflog-group %d\n",
                L7_CHAINS[ch], wan, specs[p].dport, specs[p].connbytes_max, group);
            if (n < 0 || (size_t)n >= out_size - off) return -1;
            off += (size_t)n;
        }

        if (!cfg->l7_enable_quic) continue;
        if (dump_has_rule(dump, L7_CHAINS[ch], wan, "udp", 443, group)) continue;
        int n = snprintf(out + off, out_size - off,
            "-A %s -o %s -p udp --dport 443 -m length --length 1200: "
            "-j NFLOG --nflog-group %d\n",
            L7_CHAINS[ch], wan, group);
        if (n < 0 || (size_t)n >= out_size - off) return -1;
        off += (size_t)n;
    }
    return (int)off;
}

int l7_firewall_remove(const config_t *cfg, const char *wan_iface) {
    if (!wan_iface || wan_iface[0] == '\0') return -1;

    char o_tok[MAX_INTERFACE_NAME + 8], g_tok[32];
    snprintf(o_tok, sizeof(o_tok), "-o %s ", wan_iface);
    snprintf(g_tok, sizeof(g_tok), "--nflog-group %d", l7_nflog_group(cfg));

    for (int c = 0; c < 2; c++)
        for (int ch = 0; ch < 2; ch++)
            iptables_delete_rules_matching(L7_CMDS[c], L7_CHAINS[ch], o_tok, g_tok);

    return 0;
}
