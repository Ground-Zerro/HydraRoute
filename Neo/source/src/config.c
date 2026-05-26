#include "../include/config.h"
#include "../include/params.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

static void apply_kv(config_t *cfg, const param_def_t *p, const char *val) {
    void *field = (char *)cfg + p->cfg_offset;

    switch (p->type) {
    case PT_BOOL:
        *(int *)field = (strcmp(val, "true") == 0) ? 1 : 0;
        return;

    case PT_INT: {
        errno = 0;
        long v = strtol(val, NULL, 10);
        if (errno != 0)
            LOG_WARN("Invalid %s value: %s", p->config_key, val);
        else
            *(int *)field = (int)v;
        return;
    }

    case PT_INT_POS: {
        errno = 0;
        long v = strtol(val, NULL, 10);
        if (errno != 0 || v <= 0)
            LOG_WARN("Invalid %s value: %s", p->config_key, val);
        else
            *(int *)field = (int)v;
        return;
    }

    case PT_STRING:
    case PT_PATH: {
        char *buf = (char *)field;
        strncpy(buf, val, p->buf_size - 1);
        buf[p->buf_size - 1] = '\0';
        return;
    }

    case PT_REPEAT_PATH: {
        int *cnt = (int *)((char *)cfg + p->cfg_count_offset);
        if (*cnt >= MAX_GEO_FILES) return;
        char (*arr)[MAX_PATH_LEN] = (char (*)[MAX_PATH_LEN])field;
        strncpy(arr[*cnt], val, p->buf_size - 1);
        arr[*cnt][p->buf_size - 1] = '\0';
        (*cnt)++;
        return;
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
        return;
    }
    }
}

int config_read(const char *path, config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    for (int i = 0; i < PARAMS_COUNT; i++) {
        const param_def_t *p = &PARAMS[i];
        if (p->default_int &&
            (p->type == PT_BOOL || p->type == PT_INT || p->type == PT_INT_POS)) {
            *(int *)((char *)cfg + p->cfg_offset) = p->default_int;
        } else if (p->help_default &&
                   (p->type == PT_STRING || p->type == PT_PATH)) {
            char *buf = (char *)cfg + p->cfg_offset;
            strncpy(buf, p->help_default, p->buf_size - 1);
            buf[p->buf_size - 1] = '\0';
        }
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERROR("Cannot open config: %s: %s", path, strerror(errno));
        return -1;
    }

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        char *trimmed = trim_whitespace(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#') continue;

        char *eq = strchr(trimmed, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = trim_whitespace(trimmed);
        char *val = trim_whitespace(eq + 1);

        const param_def_t *p = NULL;
        for (int i = 0; i < PARAMS_COUNT; i++) {
            if (strcmp(key, PARAMS[i].config_key) == 0) { p = &PARAMS[i]; break; }
        }
        if (p) apply_kv(cfg, p, val);
    }

    fclose(f);
    return 0;
}

#define GENCONFIG_FILENAME "hrneo.conf"

static int resolve_genconfig_path(const char *target, char *out, size_t out_size) {
    if (!target || target[0] == '\0') {
        char exe[MAX_PATH_LEN];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (n <= 0) return -1;
        exe[n] = '\0';
        char *slash = strrchr(exe, '/');
        if (slash) *slash = '\0';
        else { exe[0] = '.'; exe[1] = '\0'; }
        int dirmax = (int)out_size - (int)sizeof(GENCONFIG_FILENAME) - 1;
        if (dirmax < 1) return -1;
        snprintf(out, out_size, "%.*s/%s", dirmax, exe, GENCONFIG_FILENAME);
        return 0;
    }

    size_t tlen = strlen(target);
    if (tlen == 0 || tlen >= out_size) return -1;

    struct stat st;
    int is_dir = (target[tlen - 1] == '/') ||
                 (stat(target, &st) == 0 && S_ISDIR(st.st_mode));
    if (is_dir) {
        const char *sep = (target[tlen - 1] == '/') ? "" : "/";
        int dirmax = (int)out_size - (int)sizeof(GENCONFIG_FILENAME) - 1;
        if (dirmax < 1) return -1;
        snprintf(out, out_size, "%.*s%s%s", dirmax, target, sep, GENCONFIG_FILENAME);
    } else {
        strncpy(out, target, out_size - 1);
        out[out_size - 1] = '\0';
    }
    return 0;
}

int config_generate(const char *target) {
    char path[MAX_PATH_LEN];
    if (resolve_genconfig_path(target, path, sizeof(path)) != 0) {
        fprintf(stderr, "hrneo: cannot resolve config output path\n");
        return 1;
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "hrneo: cannot write %s: %s\n", path, strerror(errno));
        return 1;
    }

    for (int i = 0; i < PARAMS_COUNT; i++) {
        const param_def_t *p = &PARAMS[i];
        switch (p->type) {
        case PT_BOOL:
            fprintf(f, "%s=%s\n", p->config_key, p->default_int ? "true" : "false");
            break;
        case PT_INT:
        case PT_INT_POS:
            fprintf(f, "%s=%d\n", p->config_key, p->default_int);
            break;
        case PT_STRING:
        case PT_PATH:
            fprintf(f, "%s=%s\n", p->config_key,
                    p->help_default ? p->help_default : "");
            break;
        case PT_REPEAT_PATH:
        case PT_POLICY_ORDER:
            fprintf(f, "%s=\n", p->config_key);
            break;
        }
    }

    fclose(f);
    printf("hrneo: default config written to %s\n", path);
    return 0;
}
