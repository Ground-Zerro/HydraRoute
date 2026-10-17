#include "../include/config.h"
#include "../include/params.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

int config_read(const char *path, config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    for (int i = 0; i < PARAMS_COUNT; i++) {
        const param_def_t *p = &PARAMS[i];
        if (p->default_int &&
            (p->type == PT_BOOL || p->type == PT_INT || p->type == PT_INT_POS ||
             p->type == PT_INT_U16)) {
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
        if (p && param_apply(cfg, p, val, 0) != 0)
            LOG_WARN("Invalid %s value: %s", p->config_key, val);
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
        case PT_INT_U16:
            fprintf(f, "%s=%d\n", p->config_key, p->default_int);
            break;
        case PT_STRING:
        case PT_PATH:
            fprintf(f, "%s=%s\n", p->config_key,
                    p->help_default ? p->help_default : "");
            break;
        case PT_REPEAT_PATH:
        case PT_NAME_LIST:
            fprintf(f, "%s=\n", p->config_key);
            break;
        }
    }

    fclose(f);
    printf("hrneo: default config written to %s\n", path);
    return 0;
}

keenetic_token_result_t config_set_keenetic_token(const char *path, const char *token) {
    if (!token || token[0] == '\0' || strlen(token) >= MAX_RCI_TOKEN)
        return KTOKEN_INVALID;
    for (const char *p = token; *p; p++) {
        unsigned char ch = (unsigned char)*p;
        if (ch <= 0x20 || ch >= 0x7f) return KTOKEN_INVALID;
    }

    char *content;
    long len = 0;
    FILE *f = fopen(path, "r");
    if (f) {
        fseek(f, 0, SEEK_END);
        len = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (len < 0) len = 0;
        if (len > (1 << 20)) len = 1 << 20;
        content = malloc((size_t)len + 1);
        if (!content) { fclose(f); return KTOKEN_IO_ERROR; }
        len = (long)fread(content, 1, (size_t)len, f);
        content[len] = '\0';
        fclose(f);
    } else {
        content = malloc(1);
        if (!content) return KTOKEN_IO_ERROR;
        content[0] = '\0';
    }

    size_t out_cap = (size_t)len + MAX_RCI_TOKEN + 32;
    char *out = malloc(out_cap);
    if (!out) { free(content); return KTOKEN_IO_ERROR; }
    size_t out_len = 0;

    int found = 0;
    keenetic_token_result_t result = KTOKEN_ADDED;

    const char *line = content;
    for (;;) {
        const char *nl = strchr(line, '\n');
        size_t seg_len = nl ? (size_t)(nl - line) : strlen(line);
        if (!nl && seg_len == 0) break;

        int replaced = 0;
        if (!found) {
            char tmp[4096];
            size_t cplen = seg_len < sizeof(tmp) - 1 ? seg_len : sizeof(tmp) - 1;
            memcpy(tmp, line, cplen);
            tmp[cplen] = '\0';
            char *trimmed = trim_whitespace(tmp);
            if (trimmed[0] != '#' && trimmed[0] != '\0') {
                char *eq = strchr(trimmed, '=');
                if (eq) {
                    char *val = eq + 1;
                    *eq = '\0';
                    if (strcmp(trim_whitespace(trimmed), "rciToken") == 0) {
                        found = 1;
                        replaced = 1;
                        char *curval = trim_whitespace(val);
                        if (strcmp(curval, token) == 0) {
                            result = KTOKEN_UNCHANGED;
                            memcpy(out + out_len, line, seg_len);
                            out_len += seg_len;
                        } else {
                            result = curval[0] == '\0' ? KTOKEN_ADDED : KTOKEN_UPDATED;
                            out_len += (size_t)snprintf(out + out_len, out_cap - out_len,
                                                        "rciToken=%s", token);
                        }
                    }
                }
            }
        }
        if (!replaced) {
            memcpy(out + out_len, line, seg_len);
            out_len += seg_len;
        }

        if (nl) { out[out_len++] = '\n'; line = nl + 1; }
        else break;
    }

    if (!found) {
        if (out_len > 0 && out[out_len - 1] != '\n')
            out[out_len++] = '\n';
        out_len += (size_t)snprintf(out + out_len, out_cap - out_len, "rciToken=%s\n", token);
        result = KTOKEN_ADDED;
    }

    if (result == KTOKEN_UNCHANGED) {
        free(content);
        free(out);
        return result;
    }

    char tmp_path[MAX_PATH_LEN + 8];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    FILE *wf = fopen(tmp_path, "w");
    if (!wf) { free(content); free(out); return KTOKEN_IO_ERROR; }
    int wok = fwrite(out, 1, out_len, wf) == out_len;
    if (fclose(wf) != 0) wok = 0;
    free(content);
    free(out);
    if (!wok) { unlink(tmp_path); return KTOKEN_IO_ERROR; }
    if (rename(tmp_path, path) != 0) { unlink(tmp_path); return KTOKEN_IO_ERROR; }
    return result;
}
