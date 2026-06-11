#include "../include/args.h"
#include "../include/params.h"
#include <stdio.h>
#include <string.h>

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

        if (param_apply(&out->overlay, p, val, 1) != 0) {
            fprintf(stderr, "hrneo: invalid value '%s' for %s\n", val, arg);
            return -1;
        }
        out->set_mask |= p->set_bit;
    }

    return 0;
}

void args_apply(const cli_args_t *args, config_t *cfg) {
    const config_t *src = &args->overlay;

    for (int i = 0; i < PARAMS_COUNT; i++) {
        const param_def_t *p = &PARAMS[i];
        if (!(args->set_mask & p->set_bit)) continue;

        void *dst_field = (char *)cfg + p->cfg_offset;
        const void *src_field = (const char *)src + p->cfg_offset;

        switch (p->type) {
        case PT_BOOL:
        case PT_INT:
        case PT_INT_POS:
            *(int *)dst_field = *(const int *)src_field;
            break;

        case PT_STRING:
        case PT_PATH:
            memcpy(dst_field, src_field, p->buf_size);
            break;

        case PT_REPEAT_PATH: {
            int n = *(const int *)((const char *)src + p->cfg_count_offset);
            memcpy(dst_field, src_field, (size_t)n * MAX_PATH_LEN);
            *(int *)((char *)cfg + p->cfg_count_offset) = n;
            break;
        }

        case PT_POLICY_ORDER: {
            int n = *(const int *)((const char *)src + p->cfg_count_offset);
            memcpy(dst_field, src_field, (size_t)n * 64);
            *(int *)((char *)cfg + p->cfg_count_offset) = n;
            break;
        }
        }
    }
}
