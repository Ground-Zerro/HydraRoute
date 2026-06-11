#ifndef PARAMS_H
#define PARAMS_H

#include "hrneo.h"
#include <stddef.h>
#include <stdint.h>

/* One row per configurable parameter — single source of truth driving
 * config_read (key=val), args_parse (--flag val), args_apply (CLI→config),
 * and print_help. Adding a new parameter requires only an entry here plus
 * a matching field in config_t. */
typedef enum {
    PT_BOOL,
    PT_INT,
    PT_INT_POS,         /* int, must be > 0 */
    PT_STRING,          /* fixed-size text buffer */
    PT_PATH,            /* STRING with buf_size = MAX_PATH_LEN */
    PT_REPEAT_PATH,     /* char[N][MAX_PATH_LEN] + count; --flag appends */
    PT_POLICY_ORDER,    /* char[N][64] + count; single --flag, comma-split */
} param_type_t;

typedef struct {
    const char    *config_key;        /* "autoStart"            */
    const char    *cli_flag;          /* "--autoStart"          */
    param_type_t   type;
    size_t         cfg_offset;        /* offsetof(config_t, ...) */
    size_t         cfg_count_offset;  /* array count field; 0 if N/A */
    uint32_t       set_bit;           /* bit in cli_args_t.set_mask */
    size_t         buf_size;          /* STRING/PATH buffer size */
    int            default_int;       /* BOOL/INT default */
    const char    *help_arg;          /* "<true|false>", "<path>", … */
    const char    *help_text;
    const char    *help_default;      /* shown as `default: <text>` line */
} param_def_t;

extern const param_def_t PARAMS[];
extern const int PARAMS_COUNT;

int param_apply(config_t *cfg, const param_def_t *p, const char *val, int strict);

#endif
