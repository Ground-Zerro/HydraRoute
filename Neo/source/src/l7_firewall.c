#include "../include/l7_firewall.h"
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

static int build_rule_argv(char **out, char buf[][64],
                           const char *cmd, const char *op, const char *chain,
                           const char *wan, int dport, int connbytes_max,
                           int group) {
    int i = 0;
    snprintf(buf[0],  64, "%s", cmd);     out[i++] = buf[0];
    snprintf(buf[1],  64, "-w");          out[i++] = buf[1];
    snprintf(buf[2],  64, "-t");          out[i++] = buf[2];
    snprintf(buf[3],  64, "mangle");      out[i++] = buf[3];
    snprintf(buf[4],  64, "%s", op);      out[i++] = buf[4];
    snprintf(buf[5],  64, "%s", chain);   out[i++] = buf[5];
    snprintf(buf[6],  64, "-o");          out[i++] = buf[6];
    snprintf(buf[7],  64, "%s", wan);     out[i++] = buf[7];
    snprintf(buf[8],  64, "-p");          out[i++] = buf[8];
    snprintf(buf[9],  64, "tcp");         out[i++] = buf[9];
    snprintf(buf[10], 64, "--dport");     out[i++] = buf[10];
    snprintf(buf[11], 64, "%d", dport);   out[i++] = buf[11];
    snprintf(buf[12], 64, "--tcp-flags"); out[i++] = buf[12];
    snprintf(buf[13], 64, "SYN,ACK");     out[i++] = buf[13];
    snprintf(buf[14], 64, "ACK");         out[i++] = buf[14];
    snprintf(buf[15], 64, "-m");          out[i++] = buf[15];
    snprintf(buf[16], 64, "connbytes");   out[i++] = buf[16];
    snprintf(buf[17], 64, "--connbytes-dir=original"); out[i++] = buf[17];
    snprintf(buf[18], 64, "--connbytes-mode=packets"); out[i++] = buf[18];
    snprintf(buf[19], 64, "--connbytes");  out[i++] = buf[19];
    snprintf(buf[20], 64, "2:%d", connbytes_max); out[i++] = buf[20];
    snprintf(buf[21], 64, "-m");           out[i++] = buf[21];
    snprintf(buf[22], 64, "length");       out[i++] = buf[22];
    snprintf(buf[23], 64, "--length");     out[i++] = buf[23];
    snprintf(buf[24], 64, "60:");          out[i++] = buf[24];
    snprintf(buf[25], 64, "-j");           out[i++] = buf[25];
    snprintf(buf[26], 64, "NFLOG");        out[i++] = buf[26];
    snprintf(buf[27], 64, "--nflog-group"); out[i++] = buf[27];
    snprintf(buf[28], 64, "%d", group);    out[i++] = buf[28];
    out[i] = NULL;
    return i;
}

static int rule_exists(const char *cmd, const char *chain, const char *wan,
                       int dport, int connbytes_max, int group) {
    char abuf[32][64];
    char *argv[33];
    build_rule_argv(argv, abuf, cmd, "-C", chain, wan, dport, connbytes_max, group);
    char out[256];
    int rc = run_command_output(cmd, argv, out, sizeof(out));
    return rc == 0;
}

static int apply_one(const char *cmd, const char *op, const char *chain,
                     const char *wan, int dport, int connbytes_max, int group) {
    char abuf[32][64];
    char *argv[33];
    build_rule_argv(argv, abuf, cmd, op, chain, wan, dport, connbytes_max, group);
    char out[256];
    return run_command_output(cmd, argv, out, sizeof(out));
}

static const char *const L7_CMDS[]   = {"iptables", "ip6tables"};
static const char *const L7_CHAINS[] = {"FORWARD", "OUTPUT"};

typedef struct {
    int dport;
    int connbytes_max;
} l7_rule_spec_t;

static int l7_rule_specs(const config_t *cfg, l7_rule_spec_t specs[2]) {
    int max443 = cfg->l7_connbytes_max > 0 ? cfg->l7_connbytes_max : 8;
    specs[0].dport = 443;
    specs[0].connbytes_max = max443;
    specs[1].dport = 80;
    specs[1].connbytes_max = max443 < 4 ? max443 : 4;
    return cfg->l7_nflog_group > 0 ? cfg->l7_nflog_group : 210;
}

int l7_firewall_install(const config_t *cfg, const char *wan_iface) {
    if (!wan_iface || wan_iface[0] == '\0') return -1;
    l7_rule_spec_t specs[2];
    int group = l7_rule_specs(cfg, specs);
    int installed = 0, present = 0;

    for (int c = 0; c < 2; c++) {
        for (int ch = 0; ch < 2; ch++) {
            for (int p = 0; p < 2; p++) {
                if (rule_exists(L7_CMDS[c], L7_CHAINS[ch], wan_iface,
                                specs[p].dport, specs[p].connbytes_max, group)) {
                    present++;
                    continue;
                }
                if (apply_one(L7_CMDS[c], "-A", L7_CHAINS[ch], wan_iface,
                              specs[p].dport, specs[p].connbytes_max, group) == 0) {
                    installed++;
                } else {
                    LOG_WARN("L7 firewall: %s -A %s dport=%d failed",
                             L7_CMDS[c], L7_CHAINS[ch], specs[p].dport);
                }
            }
        }
    }
    if (installed > 0)
        LOG_INFO("L7 firewall rules installed (new=%d, already present=%d, wan=%s, nflog-group=%d)",
                 installed, present, wan_iface, group);
    return 0;
}

int l7_firewall_remove(const config_t *cfg, const char *wan_iface) {
    if (!wan_iface || wan_iface[0] == '\0') return -1;
    l7_rule_spec_t specs[2];
    int group = l7_rule_specs(cfg, specs);

    for (int c = 0; c < 2; c++) {
        for (int ch = 0; ch < 2; ch++) {
            for (int p = 0; p < 2; p++) {
                while (rule_exists(L7_CMDS[c], L7_CHAINS[ch], wan_iface,
                                   specs[p].dport, specs[p].connbytes_max, group)) {
                    if (apply_one(L7_CMDS[c], "-D", L7_CHAINS[ch], wan_iface,
                                  specs[p].dport, specs[p].connbytes_max, group) != 0)
                        break;
                }
            }
        }
    }
    return 0;
}
