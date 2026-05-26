#include "../include/args.h"
#include "../include/params.h"
#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define HELP_FLAG_WIDTH 33

static void print_help(void) {
    printf("Usage: hrneo [OPTIONS]\n\n");
    printf("  %-*s  %s\n", HELP_FLAG_WIDTH, "--config <path>", "Config file path");
    printf("  %-*s    default: %s\n", HELP_FLAG_WIDTH, "", DEFAULT_CONFIG_PATH);

    for (int i = 0; i < PARAMS_COUNT; i++) {
        const param_def_t *p = &PARAMS[i];
        char flagspec[80];
        snprintf(flagspec, sizeof(flagspec), "%s %s", p->cli_flag, p->help_arg);
        printf("  %-*s  %s\n", HELP_FLAG_WIDTH, flagspec, p->help_text);
        if (p->help_default)
            printf("  %-*s    default: %s\n", HELP_FLAG_WIDTH, "", p->help_default);
    }

    printf("  %-*s  %s\n", HELP_FLAG_WIDTH, "--genconfig [path]",
           "Write default config (hrneo.conf) and exit");
    printf("  %-*s    %s\n", HELP_FLAG_WIDTH, "",
           "no path: next to the binary; path is a dir: <dir>/hrneo.conf;");
    printf("  %-*s    %s\n", HELP_FLAG_WIDTH, "",
           "path is a file: written as given");
    printf("  %-*s  %s\n", HELP_FLAG_WIDTH, "--version, -v", "Print version and exit");
    printf("  %-*s  %s\n", HELP_FLAG_WIDTH, "--help, -h",    "Print this help and exit");
    printf("\nPriority: CLI flags > config file > built-in defaults\n");
}

static int parse_int(const char *val, int *out, int must_be_positive) {
    char *end;
    errno = 0;
    long v = strtol(val, &end, 10);
    if (errno != 0 || *end != '\0' || end == val) return -1;
    if (must_be_positive && v <= 0) return -1;
    *out = (int)v;
    return 0;
}

static int apply_cli_value(cli_args_t *args, const param_def_t *p, const char *val) {
    void *field = (char *)args + p->args_offset;

    switch (p->type) {
    case PT_BOOL:
        if (strcmp(val, "true") == 0)  { *(int *)field = 1; return 0; }
        if (strcmp(val, "false") == 0) { *(int *)field = 0; return 0; }
        return -1;

    case PT_INT:
        return parse_int(val, (int *)field, 0);

    case PT_INT_POS:
        return parse_int(val, (int *)field, 1);

    case PT_STRING:
    case PT_PATH: {
        char *buf = (char *)field;
        strncpy(buf, val, p->buf_size - 1);
        buf[p->buf_size - 1] = '\0';
        return 0;
    }

    case PT_REPEAT_PATH: {
        int *cnt = (int *)((char *)args + p->args_count_offset);
        if (*cnt < MAX_GEO_FILES) {
            char (*arr)[MAX_PATH_LEN] = (char (*)[MAX_PATH_LEN])field;
            strncpy(arr[*cnt], val, p->buf_size - 1);
            arr[*cnt][p->buf_size - 1] = '\0';
            (*cnt)++;
        }
        return 0;
    }

    case PT_POLICY_ORDER: {
        int *cnt = (int *)((char *)args + p->args_count_offset);
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

int args_parse(int argc, char *argv[], cli_args_t *out) {
    memset(out, 0, sizeof(*out));

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--version") == 0 || strcmp(arg, "-v") == 0) {
            printf("hrneo v%s\n", VERSION);
            return 1;
        }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_help();
            return 2;
        }
        if (strcmp(arg, "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "hrneo: missing value for --config\n");
                return -1;
            }
            const char *val = argv[++i];
            strncpy(out->config_path, val, MAX_PATH_LEN - 1);
            out->config_path[MAX_PATH_LEN - 1] = '\0';
            continue;
        }
        if (strcmp(arg, "--genconfig") == 0) {
            out->genconfig_target[0] = '\0';
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                strncpy(out->genconfig_target, argv[++i], MAX_PATH_LEN - 1);
                out->genconfig_target[MAX_PATH_LEN - 1] = '\0';
            }
            return 3;
        }

        const param_def_t *p = NULL;
        for (int k = 0; k < PARAMS_COUNT; k++) {
            if (strcmp(arg, PARAMS[k].cli_flag) == 0) { p = &PARAMS[k]; break; }
        }
        if (!p) {
            fprintf(stderr, "hrneo: unknown option: %s\n", arg);
            return -1;
        }

        if (i + 1 >= argc) {
            fprintf(stderr, "hrneo: missing value for %s\n", arg);
            return -1;
        }
        const char *val = argv[++i];

        if (apply_cli_value(out, p, val) != 0) {
            fprintf(stderr, "hrneo: invalid value '%s' for %s\n", val, arg);
            return -1;
        }
        out->set_mask |= p->set_bit;
    }

    return 0;
}

void args_apply(const cli_args_t *args, config_t *cfg) {
    for (int i = 0; i < PARAMS_COUNT; i++) {
        const param_def_t *p = &PARAMS[i];
        if (!(args->set_mask & p->set_bit)) continue;

        void *cfg_field = (char *)cfg + p->cfg_offset;
        const void *args_field = (const char *)args + p->args_offset;

        switch (p->type) {
        case PT_BOOL:
        case PT_INT:
        case PT_INT_POS:
            *(int *)cfg_field = *(const int *)args_field;
            break;

        case PT_STRING:
        case PT_PATH: {
            char *dst = (char *)cfg_field;
            strncpy(dst, (const char *)args_field, p->buf_size - 1);
            dst[p->buf_size - 1] = '\0';
            break;
        }

        case PT_REPEAT_PATH: {
            int *cfg_cnt = (int *)((char *)cfg + p->cfg_count_offset);
            const int *args_cnt = (const int *)((const char *)args + p->args_count_offset);
            *cfg_cnt = *args_cnt;
            char (*cfg_arr)[MAX_PATH_LEN] = (char (*)[MAX_PATH_LEN])cfg_field;
            const char (*args_arr)[MAX_PATH_LEN] = (const char (*)[MAX_PATH_LEN])args_field;
            for (int j = 0; j < *args_cnt; j++) {
                strncpy(cfg_arr[j], args_arr[j], p->buf_size - 1);
                cfg_arr[j][p->buf_size - 1] = '\0';
            }
            break;
        }

        case PT_POLICY_ORDER: {
            int *cfg_cnt = (int *)((char *)cfg + p->cfg_count_offset);
            const int *args_cnt = (const int *)((const char *)args + p->args_count_offset);
            *cfg_cnt = *args_cnt;
            char (*cfg_arr)[64] = (char (*)[64])cfg_field;
            const char (*args_arr)[64] = (const char (*)[64])args_field;
            for (int j = 0; j < *args_cnt; j++) {
                strncpy(cfg_arr[j], args_arr[j], 63);
                cfg_arr[j][63] = '\0';
            }
            break;
        }
        }
    }
}
