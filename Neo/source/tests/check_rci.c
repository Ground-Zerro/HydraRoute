#include "../src/rci.c"
#include <assert.h>

static const char SHOW_OUTPUT[] =
    "\033[K\n"
    "            token: \n"
    "                   id: 3\n"
    "          fingerprint: 03...cd\n"
    "      truncated-value: VCN...YWy\n"
    "              service: Core::Security::Authenticator\n"
    "                local: yes\n"
    "                 user: admin\n"
    "            user-data: HydraRoute\n"
    "              expires: never\n"
    "          last-access: 236\n"
    "\n"
    "            token: \n"
    "                   id: 9\n"
    "          fingerprint: 61...af\n"
    "      truncated-value: cDK...stq\n"
    "                 user: admin\n"
    "            user-data: someone-else\n"
    "              expires: never\n"
    "          last-access: 4\n"
    "\n\033[K";

static const char GENERATE_OUTPUT[] =
    "\033[K\n"
    "               id: 8\n"
    "            value: \n"
    "                   ksPNNRb3RGRMowrJDsZhC92yu3SIBA16iXVduJziQD0V51N8kCEzaMzo\n"
    "\n"
    "Core::Security::Authenticator: Added a token for user \"admin\".\n"
    "\033[K";

static void check_strip_ansi(void) {
    char out[512];
    strip_ansi("\033[Kid: 3\033[K\n", out, sizeof(out));
    assert(strcmp(out, "id: 3\n") == 0);

    strip_ansi("plain", out, sizeof(out));
    assert(strcmp(out, "plain") == 0);

    strip_ansi("\033[", out, sizeof(out));
    assert(out[0] == '\0');
}

static void check_parse_token_value(void) {
    char clean[NDMC_OUT_MAX];
    char token[MAX_RCI_TOKEN];

    strip_ansi(GENERATE_OUTPUT, clean, sizeof(clean));
    assert(ndmc_parse_token_value(clean, token, sizeof(token)) == 1);
    assert(strcmp(token, "ksPNNRb3RGRMowrJDsZhC92yu3SIBA16iXVduJziQD0V51N8kCEzaMzo") == 0);

    strip_ansi(SHOW_OUTPUT, clean, sizeof(clean));
    assert(ndmc_parse_token_value(clean, token, sizeof(token)) == 0);

    assert(ndmc_parse_token_value("value: short\n", token, sizeof(token)) == 0);
    assert(ndmc_parse_token_value("nothing here\n", token, sizeof(token)) == 0);
}

static void check_collect_token_ids(void) {
    char clean[NDMC_OUT_MAX];
    int ids[TOKEN_MAX_OWNED];

    strip_ansi(SHOW_OUTPUT, clean, sizeof(clean));

    int n = ndmc_collect_token_ids(clean, TOKEN_LABEL, ids, TOKEN_MAX_OWNED);
    assert(n == 1);
    assert(ids[0] == 3);

    n = ndmc_collect_token_ids(clean, "someone-else", ids, TOKEN_MAX_OWNED);
    assert(n == 1);
    assert(ids[0] == 9);

    n = ndmc_collect_token_ids(clean, "absent", ids, TOKEN_MAX_OWNED);
    assert(n == 0);

    n = ndmc_collect_token_ids("", TOKEN_LABEL, ids, TOKEN_MAX_OWNED);
    assert(n == 0);
}

static void check_token_send_rules(void) {
    rci_set_token("");
    assert(rci_mode() == RCI_MODE_LOCAL);
    assert(rci_should_send_token() == 0);

    rci_set_token("ksPNNRb3RGRMowrJDsZhC92yu3SIBA16iXVduJziQD0V51N8kCEzaMzo");
    assert(rci_mode() == RCI_MODE_TOKEN);
    assert(rci_should_send_token() != 0);

    g_mode = RCI_MODE_LOCAL;
    assert(rci_should_send_token() == 0);

    g_mode = RCI_MODE_BLOCKED;
    assert(rci_should_send_token() != 0);

    rci_set_token("good\ttail");
    assert(strcmp(g_rci_token, "good") == 0);

    rci_set_token("");
}

int main(void) {
    check_strip_ansi();
    check_parse_token_value();
    check_collect_token_ids();
    check_token_send_rules();
    printf("check_rci: OK\n");
    return 0;
}
