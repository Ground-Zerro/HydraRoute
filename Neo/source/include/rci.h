#ifndef RCI_H
#define RCI_H

#include "hrneo.h"

#define RCI_PORT DEFAULT_API_PORT

int rci_create_policies(const char (*names)[64], int count);
int rci_get_policy_mark(const char *name, char *mark, int mark_size);
void rci_set_token(const char *token);

#endif
