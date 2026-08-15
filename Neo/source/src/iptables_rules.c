#include "../include/iptables_rules.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_RULE_TOKENS 256
#define MAX_ORDER_TARGETS 256
#define FULL_MARK_MASK UINT32_C(0xffffffff)

typedef struct {
    const char *ptr;
    size_t len;
} rule_token_t;

static int valid_ipset_name(const char *ipset_name) {
    if (!ipset_name || ipset_name[0] == '\0' || strlen(ipset_name) >= 64)
        return 0;
    for (const unsigned char *p = (const unsigned char *)ipset_name; *p; p++) {
        if (isspace(*p)) return 0;
    }
    return 1;
}

static int normalize_mark(const char *mark_hex, char *out, size_t out_size) {
    if (!mark_hex || !out || out_size == 0 || mark_hex[0] == '\0') return -1;

    const char *mark = mark_hex;
    if (mark[0] == '0' && (mark[1] == 'x' || mark[1] == 'X')) mark += 2;
    size_t len = strlen(mark);
    if (len == 0 || len >= out_size || len >= 16) return -1;
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)mark[i])) return -1;
    }
    memcpy(out, mark, len);
    out[len] = '\0';
    return 0;
}

static int token_equals(const rule_token_t *token, const char *value) {
    size_t value_len = strlen(value);
    return token->len == value_len && memcmp(token->ptr, value, value_len) == 0;
}

static int token_equals_n(const rule_token_t *token, const char *value,
                          size_t value_len) {
    return token->len == value_len && memcmp(token->ptr, value, value_len) == 0;
}

static int tokenize_rule(const char *line, size_t line_len,
                         rule_token_t *tokens, size_t token_capacity,
                         size_t *token_count) {
    size_t count = 0;
    size_t pos = 0;
    while (pos < line_len) {
        while (pos < line_len && (line[pos] == ' ' || line[pos] == '\t')) pos++;
        if (pos == line_len) break;
        if (count >= token_capacity) return -1;

        size_t start = pos;
        while (pos < line_len && line[pos] != ' ' && line[pos] != '\t') pos++;
        tokens[count++] = (rule_token_t){.ptr = line + start, .len = pos - start};
    }
    *token_count = count;
    return 0;
}

static int parse_hex_value(const rule_token_t *token, uint32_t *value) {
    size_t offset = 0;
    if (token->len >= 2 && token->ptr[0] == '0' &&
        (token->ptr[1] == 'x' || token->ptr[1] == 'X'))
        offset = 2;
    if (offset == token->len || token->len - offset > 8) return -1;

    uint32_t parsed = 0;
    for (size_t i = offset; i < token->len; i++) {
        unsigned char c = (unsigned char)token->ptr[i];
        uint32_t digit;
        if (c >= '0' && c <= '9') digit = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = (uint32_t)(c - 'A' + 10);
        else return -1;
        parsed = (parsed << 4) | digit;
    }
    *value = parsed;
    return 0;
}

static int parse_mark_mask(const rule_token_t *token, int implicit_full_mask,
                           uint32_t *mark, uint32_t *mask) {
    const char *slash = memchr(token->ptr, '/', token->len);
    rule_token_t mark_token = *token;
    rule_token_t mask_token;
    if (slash) {
        size_t mark_len = (size_t)(slash - token->ptr);
        size_t mask_offset = mark_len + 1;
        if (mark_len == 0 || mask_offset >= token->len) return -1;
        mark_token.len = mark_len;
        mask_token.ptr = token->ptr + mask_offset;
        mask_token.len = token->len - mask_offset;
    } else if (implicit_full_mask) {
        mask_token.ptr = "0xffffffff";
        mask_token.len = strlen(mask_token.ptr);
    } else {
        return -1;
    }

    if (parse_hex_value(&mark_token, mark) != 0 ||
        parse_hex_value(&mask_token, mask) != 0)
        return -1;
    return 0;
}

static int parse_expected_mark(const char *mark_hex, uint32_t *mark) {
    if (!mark_hex || strchr(mark_hex, '/')) return -1;
    rule_token_t token = {.ptr = mark_hex, .len = strlen(mark_hex)};
    uint32_t ignored_mask;
    return parse_mark_mask(&token, 1, mark, &ignored_mask);
}

static int find_module(const rule_token_t *tokens, size_t token_count,
                       const char *module, size_t occurrence,
                       size_t *module_start, size_t *module_end) {
    size_t seen = 0;
    for (size_t i = 0; i + 1 < token_count; i++) {
        if (!token_equals(&tokens[i], "-m") ||
            !token_equals(&tokens[i + 1], module))
            continue;
        if (seen++ != occurrence) continue;

        size_t end = token_count;
        for (size_t j = i + 2; j < token_count; j++) {
            if ((token_equals(&tokens[j], "-m") ||
                 token_equals(&tokens[j], "-j") ||
                 token_equals(&tokens[j], "-g")) && j + 1 < token_count) {
                end = j;
                break;
            }
        }
        *module_start = i + 2;
        *module_end = end;
        return 0;
    }
    return -1;
}

static int module_count(const rule_token_t *tokens, size_t token_count,
                        const char *module) {
    int count = 0;
    for (size_t i = 0; i + 1 < token_count; i++) {
        if (token_equals(&tokens[i], "-m") &&
            token_equals(&tokens[i + 1], module))
            count++;
    }
    return count;
}

static int module_option(const rule_token_t *tokens, size_t start, size_t end,
                         const char *option, rule_token_t *value,
                         int *count) {
    int found = 0;
    for (size_t i = start; i < end; i++) {
        if (!token_equals(&tokens[i], option)) continue;
        found++;
        if (i + 1 >= end) return -1;
        if (value && found == 1) *value = tokens[i + 1];
    }
    if (count) *count = found;
    return 0;
}

static int modules_are_allowed(const rule_token_t *tokens, size_t token_count,
                               int allow_mark, int allow_connmark) {
    for (size_t i = 0; i + 1 < token_count; i++) {
        if (!token_equals(&tokens[i], "-m")) continue;
        if (token_equals(&tokens[i + 1], "set") ||
            (allow_mark && token_equals(&tokens[i + 1], "mark")) ||
            (allow_connmark && token_equals(&tokens[i + 1], "connmark")))
            continue;
        return 0;
    }
    return 1;
}

static int global_option(const rule_token_t *tokens, size_t token_count,
                         const char *option, rule_token_t *value, int *count) {
    int found = 0;
    for (size_t i = 0; i < token_count; i++) {
        if (!token_equals(&tokens[i], option)) continue;
        found++;
        if (i + 1 >= token_count) return -1;
        if (value && found == 1) *value = tokens[i + 1];
    }
    if (count) *count = found;
    return 0;
}

static int has_global_token(const rule_token_t *tokens, size_t token_count,
                            const char *value) {
    for (size_t i = 0; i < token_count; i++) {
        if (token_equals(&tokens[i], value)) return 1;
    }
    return 0;
}

static int consume_option_tokens(const rule_token_t *tokens, size_t token_count,
                                 const char *option, int has_value,
                                 int *consumed) {
    int found = 0;
    for (size_t i = 0; i < token_count; i++) {
        if (!token_equals(&tokens[i], option)) continue;
        found++;
        consumed[i] = 1;
        if (!has_value) continue;
        if (i + 1 >= token_count) return -1;
        consumed[i + 1] = 1;
    }
    return found;
}

static int canonical_token_sequence(const rule_token_t *tokens,
                                    size_t token_count, int allow_mark,
                                    int allow_connmark, int set_rule) {
    if (token_count > MAX_RULE_TOKENS || token_count < 2 ||
        !token_equals(&tokens[0], "-A") ||
        !token_equals(&tokens[1], "PREROUTING"))
        return 0;

    int consumed[MAX_RULE_TOKENS] = {0};
    consumed[0] = 1;
    consumed[1] = 1;

    for (size_t i = 0; i < token_count; i++) {
        if (!token_equals(&tokens[i], "-m")) continue;
        if (i + 1 >= token_count) return 0;
        if (!token_equals(&tokens[i + 1], "set") &&
            !(allow_mark && token_equals(&tokens[i + 1], "mark")) &&
            !(allow_connmark && token_equals(&tokens[i + 1], "connmark")))
            return 0;

        size_t end = token_count;
        for (size_t j = i + 2; j < token_count; j++) {
            if (token_equals(&tokens[j], "-m") ||
                token_equals(&tokens[j], "-j") ||
                token_equals(&tokens[j], "-g")) {
                end = j;
                break;
            }
        }
        consumed[i] = 1;
        consumed[i + 1] = 1;
        for (size_t j = i + 2; j < end; j++) consumed[j] = 1;
    }

    int jumps = 0;
    for (size_t i = 0; i < token_count; i++) {
        if (!token_equals(&tokens[i], "-j")) continue;
        if (i + 1 >= token_count) return 0;
        consumed[i] = 1;
        consumed[i + 1] = 1;
        jumps++;
    }
    if (jumps != 1) return 0;

    int found;
    if (set_rule) {
        found = consume_option_tokens(tokens, token_count, "--set-xmark", 1,
                                      consumed);
        if (found != 1) return 0;
    } else {
        found = consume_option_tokens(tokens, token_count, "--restore-mark", 0,
                                      consumed);
        if (found != 1) return 0;
        found = consume_option_tokens(tokens, token_count, "--nfmask", 1,
                                      consumed);
        if (found != 1) return 0;
        found = consume_option_tokens(tokens, token_count, "--ctmask", 1,
                                      consumed);
        if (found != 1) return 0;
    }

    for (size_t i = 0; i < token_count; i++) {
        if (!consumed[i]) return 0;
    }
    return 1;
}

static int exact_jump(const rule_token_t *tokens, size_t token_count) {
    int jumps = 0;
    int connmark_jumps = 0;
    for (size_t i = 0; i < token_count; i++) {
        if (!token_equals(&tokens[i], "-j")) continue;
        if (i + 1 >= token_count) return 0;
        jumps++;
        if (token_equals(&tokens[i + 1], "CONNMARK")) connmark_jumps++;
    }
    return jumps == 1 && connmark_jumps == 1;
}

static int packet_condition_matches(const rule_token_t *tokens,
                                    size_t token_count,
                                    const char *expected_condition) {
    int mark_modules = module_count(tokens, token_count, "mark");
    if (!expected_condition) {
        if (mark_modules == 0) return 1;
        if (mark_modules != 1) return 0;

        size_t start, end;
        if (find_module(tokens, token_count, "mark", 0, &start, &end) != 0 ||
            end - start != 3)
            return 0;
        rule_token_t mark_token;
        int mark_count;
        if (module_option(tokens, start, end, "--mark", &mark_token,
                          &mark_count) != 0 || mark_count != 1 ||
            !token_equals(&tokens[start], "!") ||
            !token_equals(&tokens[start + 1], "--mark"))
            return 0;
        uint32_t actual_value, actual_mask;
        if (parse_mark_mask(&mark_token, 0, &actual_value, &actual_mask) != 0)
            return 0;
        return actual_value == UINT32_C(0xffffaa0) &&
               actual_mask == UINT32_C(0xffffff0);
    }

    if (expected_condition[0] == '\0') return mark_modules == 0;

    rule_token_t expected_tokens[8];
    size_t expected_count;
    size_t expected_len = strlen(expected_condition);
    if (tokenize_rule(expected_condition, expected_len, expected_tokens,
                      sizeof(expected_tokens) / sizeof(expected_tokens[0]),
                      &expected_count) != 0)
        return 0;
    if (expected_count == 0) return mark_modules == 0;
    if (expected_count != 5 ||
        !token_equals(&expected_tokens[0], "-m") ||
        !token_equals(&expected_tokens[1], "mark") ||
        !token_equals(&expected_tokens[2], "!") ||
        !token_equals(&expected_tokens[3], "--mark"))
        return 0;

    uint32_t expected_value, expected_mask;
    if (parse_mark_mask(&expected_tokens[4], 0, &expected_value,
                        &expected_mask) != 0)
        return 0;
    if (mark_modules != 1) return 0;

    size_t start, end;
    if (find_module(tokens, token_count, "mark", 0, &start, &end) != 0 ||
        end - start != 3)
        return 0;
    if (!token_equals(&tokens[start], "!") ||
        !token_equals(&tokens[start + 1], "--mark"))
        return 0;
    rule_token_t actual_token;
    int actual_count;
    if (module_option(tokens, start, end, "--mark", &actual_token,
                      &actual_count) != 0 || actual_count != 1)
        return 0;

    uint32_t actual_value, actual_mask;
    return parse_mark_mask(&actual_token, 0, &actual_value, &actual_mask) == 0 &&
           actual_value == expected_value && actual_mask == expected_mask;
}

static int target_match(const rule_token_t *tokens, size_t token_count,
                        const char *ipset_name) {
    size_t start, end;
    if (find_module(tokens, token_count, "set", 0, &start, &end) != 0)
        return 0;
    if (end - start != 3) return 0;

    rule_token_t set_token;
    int match_count;
    if (module_option(tokens, start, end, "--match-set", &set_token,
                      &match_count) != 0 || match_count != 1)
        return 0;

    size_t option_index = start;
    while (option_index < end &&
           !token_equals(&tokens[option_index], "--match-set"))
        option_index++;
    if (option_index + 2 >= end) return 0;
    return token_equals_n(&set_token, ipset_name, strlen(ipset_name)) &&
           token_equals(&tokens[option_index + 2], "dst");
}

static int target_mentioned(const rule_token_t *tokens, size_t token_count,
                            const char *ipset_name) {
    for (size_t i = 0; i + 1 < token_count; i++) {
        if (token_equals(&tokens[i], "--match-set") &&
            token_equals_n(&tokens[i + 1], ipset_name, strlen(ipset_name)))
            return 1;
    }
    return 0;
}

static int canonical_set_rule(const rule_token_t *tokens, size_t token_count,
                              const char *ipset_name, uint32_t expected_mark,
                              const char *packet_condition) {
    if (module_count(tokens, token_count, "set") != 1 ||
        module_count(tokens, token_count, "connmark") != 1 ||
        !modules_are_allowed(tokens, token_count, 1, 1) ||
        !target_match(tokens, token_count, ipset_name) ||
        !exact_jump(tokens, token_count) ||
        has_global_token(tokens, token_count, "-g") ||
        !packet_condition_matches(tokens, token_count, packet_condition) ||
        !canonical_token_sequence(tokens, token_count, 1, 1, 1) ||
        has_global_token(tokens, token_count, "--restore-mark") ||
        has_global_token(tokens, token_count, "--nfmask") ||
        has_global_token(tokens, token_count, "--ctmask") ||
        has_global_token(tokens, token_count, "--save-mark"))
        return 0;

    size_t connmark_start, connmark_end;
    if (find_module(tokens, token_count, "connmark", 0,
                    &connmark_start, &connmark_end) != 0)
        return 0;
    if (connmark_end - connmark_start != 2) return 0;
    rule_token_t connmark_token;
    int connmark_count;
    if (module_option(tokens, connmark_start, connmark_end, "--mark",
                      &connmark_token, &connmark_count) != 0 ||
        connmark_count != 1)
        return 0;
    uint32_t connmark_value, connmark_mask;
    if (parse_mark_mask(&connmark_token, 1, &connmark_value,
                        &connmark_mask) != 0 || connmark_value != 0 ||
        connmark_mask != FULL_MARK_MASK)
        return 0;

    rule_token_t setmark_token;
    int setmark_count;
    if (global_option(tokens, token_count, "--set-xmark", &setmark_token,
                      &setmark_count) != 0 || setmark_count != 1)
        return 0;
    int setmark_alias_count;
    if (global_option(tokens, token_count, "--set-mark", NULL,
                      &setmark_alias_count) != 0 || setmark_alias_count != 0)
        return 0;
    uint32_t setmark_value, setmark_mask;
    return parse_mark_mask(&setmark_token, 0, &setmark_value,
                           &setmark_mask) == 0 &&
           setmark_value == expected_mark && setmark_mask == FULL_MARK_MASK &&
           module_count(tokens, token_count, "mark") <= 1;
}

static int canonical_restore_rule(const rule_token_t *tokens, size_t token_count,
                                  const char *ipset_name) {
    if (module_count(tokens, token_count, "set") != 1 ||
        module_count(tokens, token_count, "connmark") != 0 ||
        module_count(tokens, token_count, "mark") != 0 ||
        !modules_are_allowed(tokens, token_count, 0, 0) ||
        !target_match(tokens, token_count, ipset_name) ||
        !exact_jump(tokens, token_count) ||
        has_global_token(tokens, token_count, "-g") ||
        !canonical_token_sequence(tokens, token_count, 0, 0, 0))
        return 0;

    int restore_count, nfmask_count, ctmask_count;
    rule_token_t nfmask_token, ctmask_token;
    if (global_option(tokens, token_count, "--restore-mark", NULL,
                      &restore_count) != 0 || restore_count != 1 ||
        global_option(tokens, token_count, "--nfmask", &nfmask_token,
                      &nfmask_count) != 0 || nfmask_count != 1 ||
        global_option(tokens, token_count, "--ctmask", &ctmask_token,
                      &ctmask_count) != 0 || ctmask_count != 1)
        return 0;

    uint32_t nfmask, ctmask;
    return parse_hex_value(&nfmask_token, &nfmask) == 0 &&
           parse_hex_value(&ctmask_token, &ctmask) == 0 &&
           nfmask == FULL_MARK_MASK && ctmask == FULL_MARK_MASK;
}

static int line_is_prerouting(const rule_token_t *tokens, size_t token_count) {
    return token_count >= 2 && token_equals(&tokens[0], "-A") &&
           token_equals(&tokens[1], "PREROUTING");
}

int connmark_rule_state_for_condition(const char *dump,
                                      const char *ipset_name,
                                      const char *mark_hex,
                                      const char *packet_condition,
                                      connmark_rule_state_t *state) {
    uint32_t expected_mark;
    if (!dump || !valid_ipset_name(ipset_name) || !state ||
        parse_expected_mark(mark_hex, &expected_mark) != 0)
        return -1;

    memset(state, 0, sizeof(*state));
    state->set_rule_index = -1;
    state->restore_rule_index = -1;

    const char *line = dump;
    int line_index = 0;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        const char *end = nl ? nl : line + strlen(line);
        rule_token_t tokens[MAX_RULE_TOKENS];
        size_t token_count;
        if (tokenize_rule(line, (size_t)(end - line), tokens,
                          sizeof(tokens) / sizeof(tokens[0]),
                          &token_count) != 0)
            return -1;

        if (line_is_prerouting(tokens, token_count) &&
            target_mentioned(tokens, token_count, ipset_name)) {
            int has_setmark, has_restore, has_nfmask, has_ctmask;
            if (global_option(tokens, token_count, "--set-xmark", NULL,
                              &has_setmark) != 0 ||
                global_option(tokens, token_count, "--restore-mark", NULL,
                              &has_restore) != 0 ||
                global_option(tokens, token_count, "--nfmask", NULL,
                              &has_nfmask) != 0 ||
                global_option(tokens, token_count, "--ctmask", NULL,
                              &has_ctmask) != 0)
                return -1;

            int set_candidate = has_setmark > 0;
            int restore_candidate = has_restore > 0 || has_nfmask > 0 ||
                                    has_ctmask > 0;
            int valid_set = set_candidate && !restore_candidate &&
                            canonical_set_rule(tokens, token_count, ipset_name,
                                               expected_mark, packet_condition);
            int valid_restore = restore_candidate && !set_candidate &&
                                canonical_restore_rule(tokens, token_count,
                                                       ipset_name);

            if (valid_set) {
                if (!state->exact_set_rule)
                    state->set_rule_index = line_index;
                state->exact_set_rule = 1;
            } else if (set_candidate || !restore_candidate) {
                state->conflicting_set_rule = 1;
            }

            if (valid_restore) {
                if (!state->restore_rule)
                    state->restore_rule_index = line_index;
                state->restore_rule = 1;
            } else if (restore_candidate) {
                state->conflicting_restore_rule = 1;
                state->conflicting_set_rule = 1;
            }
        }

        line = nl ? nl + 1 : NULL;
        line_index++;
    }
    return 0;
}

int connmark_rule_state(const char *dump,
                        const char *ipset_name,
                        const char *mark_hex,
                        connmark_rule_state_t *state) {
    return connmark_rule_state_for_condition(dump, ipset_name, mark_hex,
                                              NULL, state);
}

int connmark_format_set_rule(char *out,
                             size_t out_size,
                             const char *packet_condition,
                             const char *ipset_name,
                             const char *mark_hex) {
    char normalized_mark[16];
    if (!out || out_size == 0 || !packet_condition ||
        !valid_ipset_name(ipset_name) ||
        normalize_mark(mark_hex, normalized_mark, sizeof(normalized_mark)) != 0)
        return -1;

    int n = snprintf(out, out_size,
        "-A PREROUTING %s-m connmark --mark 0x0/0xffffffff "
        "-m set --match-set %s dst -j CONNMARK "
        "--set-xmark 0x%s/0xffffffff\n",
        packet_condition, ipset_name, normalized_mark);
    if (n < 0 || (size_t)n >= out_size) return -1;
    return 0;
}

int connmark_format_restore_rule(char *out,
                                 size_t out_size,
                                 const char *ipset_name) {
    if (!out || out_size == 0 || !valid_ipset_name(ipset_name)) return -1;

    int n = snprintf(out, out_size,
        "-A PREROUTING -m set --match-set %s dst -j CONNMARK "
        "--restore-mark --nfmask 0xffffffff --ctmask 0xffffffff\n",
        ipset_name);
    if (n < 0 || (size_t)n >= out_size) return -1;
    return 0;
}

connmark_restore_action_t
connmark_restore_action(const connmark_rule_state_t *state) {
    if (!state || state->conflicting_set_rule || state->conflicting_restore_rule)
        return CONNMARK_RESTORE_DEFER;
    if (state->restore_rule && !state->exact_set_rule)
        return CONNMARK_RESTORE_DEFER;
    if (state->exact_set_rule && state->restore_rule)
        return CONNMARK_RESTORE_NONE;
    if (state->exact_set_rule)
        return CONNMARK_RESTORE_ONLY;
    return CONNMARK_RESTORE_PAIR;
}

int connmark_restore_order_safe(const char *dump,
                                const connmark_restore_target_t *targets,
                                size_t target_count) {
    if (!dump || (!targets && target_count != 0) ||
        target_count > MAX_ORDER_TARGETS)
        return -1;

    connmark_rule_state_t states[MAX_ORDER_TARGETS];
    connmark_restore_action_t actions[MAX_ORDER_TARGETS];
    for (size_t i = 0; i < target_count; i++) {
        if (connmark_rule_state_for_condition(
                dump, targets[i].ipset_name, targets[i].mark_hex,
                targets[i].packet_condition, &states[i]) != 0)
            return -1;
        actions[i] = connmark_restore_action(&states[i]);
        if (actions[i] == CONNMARK_RESTORE_DEFER) return 1;
    }

    int last_existing_index = -1;
    int last_set_index = -1;
    int last_restore_index = -1;
    for (size_t i = 0; i < target_count; i++) {
        if (states[i].set_rule_index >= 0 &&
            states[i].restore_rule_index >= 0 &&
            states[i].set_rule_index >= states[i].restore_rule_index)
            return 1;

        if (states[i].set_rule_index >= 0) {
            if (states[i].set_rule_index < last_set_index) return 1;
            last_set_index = states[i].set_rule_index;
        }
        if (states[i].restore_rule_index >= 0) {
            if (states[i].restore_rule_index < last_restore_index) return 1;
            last_restore_index = states[i].restore_rule_index;
        }

        int first_existing = states[i].set_rule_index;
        if (first_existing < 0 ||
            (states[i].restore_rule_index >= 0 &&
             states[i].restore_rule_index < first_existing))
            first_existing = states[i].restore_rule_index;

        if (first_existing >= 0) {
            if (first_existing < last_existing_index) return 1;
            last_existing_index = first_existing;
        }

        if (actions[i] == CONNMARK_RESTORE_NONE) continue;
        for (size_t j = i + 1; j < target_count; j++) {
            if (states[j].set_rule_index >= 0 ||
                states[j].restore_rule_index >= 0)
                return 1;
        }
    }
    return 0;
}
