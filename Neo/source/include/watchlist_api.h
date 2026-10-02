#ifndef WATCHLIST_API_H
#define WATCHLIST_API_H

#include "hrneo.h"

int  wlapi_start(const char *path, const domain_hashtable_t *ht);
void wlapi_stop(void);
int  wlapi_request(const char *path, const char *command, const char *arg);

#endif
