#ifndef ARGS_H
#define ARGS_H

#include "hrneo.h"
#include "config.h"
#include <stdint.h>

/* CLI flags parsed into `overlay` (a scratch config_t) via the PARAMS[] table;
 * set_mask records which parameters were given so args_apply copies only
 * those fields over the file-based config. Bit positions are owned by
 * PARAMS[] — do not test individual bits here. */
typedef struct {
    char config_path[MAX_PATH_LEN];
    char genconfig_target[MAX_PATH_LEN];
    uint32_t set_mask;
    config_t overlay;
} cli_args_t;

int  args_parse(int argc, char *argv[], cli_args_t *out);
void args_apply(const cli_args_t *args, config_t *cfg);

#endif
