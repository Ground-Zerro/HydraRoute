#ifndef CONFIG_H
#define CONFIG_H

#include "hrneo.h"

int config_read(const char *path, config_t *cfg);
int config_generate(const char *target);

#endif
