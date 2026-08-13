#include "../include/iptables_rules.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

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

static int token_equals(const char *token, size_t token_len, const char *value) {
    size_t value_len = strlen(value);
    return token_len == value_len && memcmp(token, value, value_len) == 0;
}

static int next_token(const char **cursor, const char *end,
                      const char **token, size_t *token_len) {
    const char *p = *cursor;
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p == end) {
        *cursor = p;
        return 0;
    }

    const char *start = p;
    while (p < end && *p != ' ' && *p != '\t') p++;
    *cursor = p;
    *token = start;
    *token_len = (size_t)(p - start);
    return 1;
}

static int mark_token_equals(const char *token, size_t token_len,
                             const char *expected_mark) {
    const char *slash = memchr(token, '/', token_len);
    if (!slash || slash == token) return 0;

    size_t mark_offset = 0;
    size_t mark_len = (size_t)(slash - token);
    if (mark_len >= 2 && token[0] == '0' &&
        (token[1] == 'x' || token[1] == 'X')) {
        mark_offset = 2;
        mark_len -= 2;
    }

    size_t expected_len = strlen(expected_mark);
    return mark_len == expected_len &&
           memcmp(token + mark_offset, expected_mark, expected_len) == 0;
}

int connmark_rule_state(const char *dump,
                        const char *ipset_name,
                        const char *mark_hex,
                        connmark_rule_state_t *state) {
    char expected_mark[16];
    if (!dump || !valid_ipset_name(ipset_name) || !state ||
        normalize_mark(mark_hex, expected_mark, sizeof(expected_mark)) != 0)
        return -1;

    memset(state, 0, sizeof(*state));
    const char *line = dump;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        const char *end = nl ? nl : line + strlen(line);
        const char *cursor = line;
        const char *token;
        size_t token_len;

        if (!next_token(&cursor, end, &token, &token_len) ||
            !token_equals(token, token_len, "-A") ||
            !next_token(&cursor, end, &token, &token_len) ||
            !token_equals(token, token_len, "PREROUTING")) {
            line = nl ? nl + 1 : NULL;
            continue;
        }

        int target_set = 0;
        int restore_mark = 0;
        int nfmask = 0;
        int ctmask = 0;
        int set_xmark = 0;
        int set_mark_matches = 0;

        while (next_token(&cursor, end, &token, &token_len)) {
            if (token_equals(token, token_len, "--match-set")) {
                const char *set_token;
                const char *direction;
                size_t set_len;
                size_t direction_len;
                if (!next_token(&cursor, end, &set_token, &set_len) ||
                    !next_token(&cursor, end, &direction, &direction_len))
                    continue;
                if (set_len == strlen(ipset_name) &&
                    memcmp(set_token, ipset_name, set_len) == 0 &&
                    token_equals(direction, direction_len, "dst"))
                    target_set = 1;
            } else if (token_equals(token, token_len, "--set-xmark")) {
                const char *mark_token;
                size_t mark_len;
                if (!next_token(&cursor, end, &mark_token, &mark_len)) continue;
                set_xmark = 1;
                set_mark_matches = mark_token_equals(mark_token, mark_len,
                                                     expected_mark);
            } else if (token_equals(token, token_len, "--restore-mark")) {
                restore_mark = 1;
            } else if (token_equals(token, token_len, "--nfmask")) {
                const char *mask_token;
                size_t mask_len;
                if (next_token(&cursor, end, &mask_token, &mask_len) &&
                    token_equals(mask_token, mask_len, "0xffffffff"))
                    nfmask = 1;
            } else if (token_equals(token, token_len, "--ctmask")) {
                const char *mask_token;
                size_t mask_len;
                if (next_token(&cursor, end, &mask_token, &mask_len) &&
                    token_equals(mask_token, mask_len, "0xffffffff"))
                    ctmask = 1;
            }
        }

        if (target_set && set_xmark) {
            if (set_mark_matches)
                state->exact_set_rule = 1;
            else
                state->conflicting_set_rule = 1;
        }
        if (target_set && restore_mark && nfmask && ctmask)
            state->restore_rule = 1;

        line = nl ? nl + 1 : NULL;
    }

    return 0;
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
    if (!state || state->conflicting_set_rule)
        return CONNMARK_RESTORE_DEFER;
    if (state->restore_rule && !state->exact_set_rule)
        return CONNMARK_RESTORE_DEFER;
    if (state->exact_set_rule && state->restore_rule)
        return CONNMARK_RESTORE_NONE;
    if (state->exact_set_rule)
        return CONNMARK_RESTORE_ONLY;
    return CONNMARK_RESTORE_PAIR;
}
