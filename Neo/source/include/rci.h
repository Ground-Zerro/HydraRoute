#ifndef RCI_H
#define RCI_H

#include "hrneo.h"

#define RCI_PORT DEFAULT_API_PORT

#define RCI_MARK_OK         1
#define RCI_MARK_ABSENT     0
#define RCI_MARK_TRANSPORT  (-1)
#define RCI_MARK_DENIED     (-2)

typedef enum {
    RCI_MODE_LOCAL,
    RCI_MODE_TOKEN,
    RCI_MODE_TOKEN_REQUIRED,
    RCI_MODE_BLOCKED
} rci_mode_t;

int rci_create_policies(const char (*names)[64], int count);
int rci_get_policy_mark(const char *name, char *mark, int mark_size);
void rci_set_token(const char *token);
rci_mode_t rci_mode(void);
rci_mode_t rci_resolve_auth(void);
int rci_token_bootstrap(const char *config_path);
int rci_auth_recover(const char *config_path);

#endif
