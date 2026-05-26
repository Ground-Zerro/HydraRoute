#ifndef RCI_H
#define RCI_H

#include "hrneo.h"

#define RCI_PORT DEFAULT_API_PORT
#define RCI_MAX_RESPONSE (1024 * 1024)

typedef struct {
    char name[MAX_POLICY_NAME];
    char mark[16];
} policy_mark_t;

/* RCI HTTP/JSON client over loopback:79 to ndmsv. Holds its own scratch buffers
 * so multiple RCI instances can coexist (e.g. for tests). Allocate via init,
 * release via close. */
typedef struct {
    char *raw_buf;        /* wire-level recv buffer (RCI_MAX_RESPONSE + 4096) */
    char *response_buf;   /* RCI policy response buffer (RCI_MAX_RESPONSE)    */
} rci_client_t;

int  rci_client_init(rci_client_t *c);
void rci_client_close(rci_client_t *c);

int rci_get_policies_with_retry(rci_client_t *c, policy_mark_t *policies, int max_policies);
int rci_create_policies(rci_client_t *c, const char (*names)[64], int count);

#endif
