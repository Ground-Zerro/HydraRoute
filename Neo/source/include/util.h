#ifndef UTIL_H
#define UTIL_H

#include "hrneo.h"
#include <stdlib.h>
#include <string.h>

domain_hashtable_t *ht_create(void);
void ht_destroy(domain_hashtable_t *ht);
int ht_insert(domain_hashtable_t *ht, const char *domain, size_t domain_len, const char *ipset_name, int match_subs);
domain_entry_t *ht_lookup(const domain_hashtable_t *ht, const char *domain, size_t domain_len);

void to_lower_inplace(char *s, size_t len);
char *trim_whitespace(char *s);
int mkdir_p(const char *path, int mode);
int run_command_output(const char *cmd, char *const argv[], char *output, size_t output_size);
int run_command_stdin(const char *cmd, char *const argv[], const char *input, size_t input_len);

#endif
