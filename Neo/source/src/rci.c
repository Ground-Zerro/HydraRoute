#include "../include/rci.h"
#include "../include/log.h"
#include "../include/util.h"
#include "../include/config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define RCI_RAW_MAX      32768
#define RCI_ERR_TRANSPORT (-1)
#define RCI_ERR_DENIED    (-2)
#define RCI_ERR_HTTP      (-3)

#define RCI_PROBE_PATH   "/rci/show/version"
#define RCI_RECOVER_MIN_SEC 10

#define NDMC_PATH        "/bin/ndmc"
#define NDMC_OUT_MAX     8192
#define TOKEN_LABEL      "HydraRoute"
#define TOKEN_MIN_LEN    16
#define TOKEN_MAX_OWNED  16

static char g_rci_token[MAX_RCI_TOKEN];
static rci_mode_t g_mode = RCI_MODE_LOCAL;
static int g_auth_stale;
static int g_mode_logged;
static time_t g_last_recover;

void rci_set_token(const char *token) {
    int j = 0;
    if (token) {
        for (int i = 0; token[i] && j < MAX_RCI_TOKEN - 1; i++) {
            unsigned char ch = (unsigned char)token[i];
            if (ch <= 0x20 || ch >= 0x7f) break;
            g_rci_token[j++] = (char)ch;
        }
        if (token[j] != '\0')
            LOG_WARN("rciToken truncated at unsupported character, using first %d chars", j);
    }
    g_rci_token[j] = '\0';
    g_mode = g_rci_token[0] ? RCI_MODE_TOKEN : RCI_MODE_LOCAL;
}

rci_mode_t rci_mode(void) {
    return g_mode;
}

static int rci_should_send_token(void) {
    return g_rci_token[0] && g_mode != RCI_MODE_LOCAL && g_mode != RCI_MODE_TOKEN_REQUIRED;
}

static int rci_connect(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = RCI_TIMEOUT_SEC };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(RCI_PORT);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int rci_request_ex(const char *method, const char *path,
                          const char *body, int body_len,
                          char *response, int response_max,
                          int use_token, int *http_status) {
    if (http_status) *http_status = 0;

    int fd = rci_connect();
    if (fd < 0) {
        LOG_ERROR("RCI connect failed: %s", strerror(errno));
        return RCI_ERR_TRANSPORT;
    }

    char tkn_hdr[MAX_RCI_TOKEN + 24];
    if (use_token && g_rci_token[0])
        snprintf(tkn_hdr, sizeof(tkn_hdr), "X-NDMA-TKN: %s\r\n", g_rci_token);
    else
        tkn_hdr[0] = '\0';

    char header[MAX_RCI_TOKEN + 512];
    int hlen;
    if (body && body_len > 0) {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "%s"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "\r\n",
            method, path, tkn_hdr, body_len);
    } else {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "%s"
            "\r\n",
            method, path, tkn_hdr);
    }

    if (send(fd, header, hlen, 0) != hlen) {
        close(fd);
        return RCI_ERR_TRANSPORT;
    }

    if (body && body_len > 0) {
        int total = 0;
        while (total < body_len) {
            int n = send(fd, body + total, body_len - total, 0);
            if (n <= 0) { close(fd); return RCI_ERR_TRANSPORT; }
            total += n;
        }
    }

    static char raw[RCI_RAW_MAX];
    int total = 0;
    int max_raw = (int)sizeof(raw) - 1;
    while (total < max_raw) {
        int n = recv(fd, raw + total, max_raw - total, 0);
        if (n <= 0) break;
        total += n;
    }
    raw[total] = '\0';
    close(fd);

    char *body_start = strstr(raw, "\r\n\r\n");
    if (!body_start) return RCI_ERR_TRANSPORT;
    body_start += 4;

    if (strncmp(raw, "HTTP/", 5) != 0) return RCI_ERR_TRANSPORT;
    char *status_pos = strchr(raw, ' ');
    if (!status_pos) return RCI_ERR_TRANSPORT;

    int status = atoi(status_pos + 1);
    if (http_status) *http_status = status;

    if (status == 401 || status == 403) {
        g_auth_stale = 1;
        return RCI_ERR_DENIED;
    }
    if (status != 200) return RCI_ERR_HTTP;

    int response_len = total - (int)(body_start - raw);
    if (response_len > response_max - 1) response_len = response_max - 1;
    memcpy(response, body_start, response_len);
    response[response_len] = '\0';

    return response_len;
}

static int rci_request(const char *method, const char *path,
                       const char *body, int body_len,
                       char *response, int response_max) {
    return rci_request_ex(method, path, body, body_len, response, response_max,
                          rci_should_send_token(), NULL);
}

static int rci_probe(int use_token) {
    char response[512];
    int status = 0;
    rci_request_ex("GET", RCI_PROBE_PATH, NULL, 0, response, sizeof(response),
                   use_token, &status);
    return status;
}

static void rci_log_mode(void) {
    switch (g_mode) {
    case RCI_MODE_LOCAL:
        if (g_rci_token[0])
            LOG_WARN("Router rejected rciToken, falling back to unauthenticated RCI "
                     "while the firmware still allows it");
        else
            LOG_INFO("RCI accepts unauthenticated local requests, token not needed");
        break;
    case RCI_MODE_TOKEN:
        LOG_INFO("RCI authenticated with X-NDMA-TKN");
        break;
    case RCI_MODE_TOKEN_REQUIRED:
        LOG_ERROR("RCI requires an access token but rciToken is empty");
        break;
    case RCI_MODE_BLOCKED:
        LOG_ERROR("RCI requires an access token and the current rciToken is rejected");
        break;
    }
}

rci_mode_t rci_resolve_auth(void) {
    rci_mode_t before = g_mode;
    g_auth_stale = 0;

    if (g_rci_token[0] == '\0') {
        int status = rci_probe(0);
        if (status == 0) { g_auth_stale = 1; return g_mode; }
        g_mode = (status == 200) ? RCI_MODE_LOCAL : RCI_MODE_TOKEN_REQUIRED;
    } else {
        int status = rci_probe(1);
        if (status == 0) { g_auth_stale = 1; return g_mode; }
        if (status == 200) {
            g_mode = RCI_MODE_TOKEN;
        } else {
            int plain = rci_probe(0);
            if (plain == 0) { g_auth_stale = 1; return g_mode; }
            g_mode = (plain == 200) ? RCI_MODE_LOCAL : RCI_MODE_BLOCKED;
        }
    }

    if (g_mode != before || !g_mode_logged) {
        rci_log_mode();
        g_mode_logged = 1;
    }
    return g_mode;
}

static int token_char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '+' || c == '/' || c == '=' || c == '-' || c == '_';
}

static void strip_ansi(const char *in, char *out, int out_size) {
    int j = 0;
    for (int i = 0; in[i] && j < out_size - 1; i++) {
        if ((unsigned char)in[i] == 0x1b) {
            if (in[i + 1] == '[') {
                i += 2;
                while (in[i] && !((unsigned char)in[i] >= 0x40 && (unsigned char)in[i] <= 0x7e)) i++;
                if (!in[i]) break;
            }
            continue;
        }
        out[j++] = in[i];
    }
    out[j] = '\0';
}

static int ndmc_exec(const char *command, char *out, int out_size) {
    char *argv[] = { (char *)NDMC_PATH, (char *)"-c", (char *)command, NULL };
    out[0] = '\0';
    return run_command_output(NDMC_PATH, argv, out, (size_t)out_size);
}

static const char *line_field(const char *line, const char *key) {
    while (*line == ' ' || *line == '\t') line++;
    size_t klen = strlen(key);
    if (strncmp(line, key, klen) != 0) return NULL;
    line += klen;
    while (*line == ' ' || *line == '\t') line++;
    return line;
}

static int ndmc_parse_token_value(const char *text, char *token, int token_size) {
    for (const char *line = text; *line; ) {
        const char *value = line_field(line, "value:");
        if (value) {
            while (*value == '\r' || *value == '\n' || *value == ' ' || *value == '\t') value++;
            int n = 0;
            while (n < token_size - 1 && token_char((unsigned char)value[n])) n++;
            if (n < TOKEN_MIN_LEN) return 0;
            memcpy(token, value, n);
            token[n] = '\0';
            return 1;
        }
        const char *nl = strchr(line, '\n');
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

static void copy_word(const char *src, char *buf, int buf_size) {
    int n = 0;
    while (n < buf_size - 1 && src[n] && src[n] != ' ' && src[n] != '\t' &&
           src[n] != '\r' && src[n] != '\n') n++;
    memcpy(buf, src, (size_t)n);
    buf[n] = '\0';
}

static int ndmc_collect_token_ids(const char *text, const char *label, int *ids, int max_ids) {
    int count = 0;
    int current = 0;

    for (const char *line = text; *line && count < max_ids; ) {
        const char *nl = strchr(line, '\n');
        int len = nl ? (int)(nl - line) : (int)strlen(line);

        char buf[160];
        if (len > 0 && len < (int)sizeof(buf)) {
            memcpy(buf, line, (size_t)len);
            buf[len] = '\0';

            char word[80];
            const char *field = line_field(buf, "user-data:");
            if (field) {
                copy_word(field, word, sizeof(word));
                if (current > 0 && strcmp(word, label) == 0) ids[count++] = current;
            } else if ((field = line_field(buf, "id:")) != NULL) {
                copy_word(field, word, sizeof(word));
                current = atoi(word);
            }
        }

        if (!nl) break;
        line = nl + 1;
    }
    return count;
}

static int rci_rotate_token(const char *config_path) {
    static char raw[NDMC_OUT_MAX];
    static char clean[NDMC_OUT_MAX];
    int ids[TOKEN_MAX_OWNED];
    int owned = 0;

    if (ndmc_exec("show authentication token", raw, sizeof(raw)) == 0) {
        strip_ansi(raw, clean, sizeof(clean));
        owned = ndmc_collect_token_ids(clean, TOKEN_LABEL, ids, TOKEN_MAX_OWNED);
    } else {
        LOG_WARN("ndmc: cannot list access tokens");
    }

    for (int i = 0; i < owned; i++) {
        char command[64];
        snprintf(command, sizeof(command), "authentication token delete %d", ids[i]);
        if (ndmc_exec(command, raw, sizeof(raw)) != 0)
            LOG_WARN("ndmc: failed to delete stale token %d", ids[i]);
        else
            LOG_INFO("Deleted stale RCI token %d", ids[i]);
    }

    if (ndmc_exec("authentication token generate " TOKEN_LABEL, raw, sizeof(raw)) != 0) {
        LOG_ERROR("ndmc: token generation failed");
        return -1;
    }

    strip_ansi(raw, clean, sizeof(clean));
    char token[MAX_RCI_TOKEN];
    if (!ndmc_parse_token_value(clean, token, sizeof(token))) {
        LOG_ERROR("ndmc: cannot parse generated token");
        return -1;
    }

    switch (config_set_keenetic_token(config_path, token)) {
    case KTOKEN_ADDED:
    case KTOKEN_UPDATED:
    case KTOKEN_UNCHANGED:
        LOG_INFO("Generated a new Keenetic RCI token, stored in %s", config_path);
        break;
    default:
        LOG_ERROR("Generated a Keenetic RCI token but failed to store it in %s, "
                  "it will be regenerated on next start", config_path);
        break;
    }

    rci_set_token(token);
    ndmc_exec("system configuration save", raw, sizeof(raw));
    return 0;
}

int rci_token_bootstrap(const char *config_path) {
    rci_mode_t mode = rci_resolve_auth();
    if (g_auth_stale) {
        LOG_WARN("RCI is not answering yet, authentication check deferred");
        return -1;
    }
    if (mode == RCI_MODE_LOCAL || mode == RCI_MODE_TOKEN) return 0;

    if (rci_rotate_token(config_path) != 0) return -1;

    mode = rci_resolve_auth();
    if (mode != RCI_MODE_TOKEN) {
        LOG_ERROR("Freshly generated RCI token is not accepted by the router");
        return -1;
    }
    return 0;
}

int rci_auth_recover(const char *config_path) {
    if (!g_auth_stale && g_mode != RCI_MODE_TOKEN_REQUIRED && g_mode != RCI_MODE_BLOCKED)
        return 0;

    time_t now = time(NULL);
    if (now - g_last_recover < RCI_RECOVER_MIN_SEC) return -1;
    g_last_recover = now;

    return rci_token_bootstrap(config_path);
}

int rci_get_policy_mark(const char *name, char *mark, int mark_size) {
    char path[160];
    snprintf(path, sizeof(path), "/rci/show/ip/policy/%s/mark", name);

    char response[256];
    int len = rci_request("GET", path, NULL, 0, response, sizeof(response));
    if (len == RCI_ERR_TRANSPORT) return RCI_MARK_TRANSPORT;
    if (len == RCI_ERR_DENIED) return RCI_MARK_DENIED;
    if (len < 0) return RCI_MARK_ABSENT;

    const char *val = strchr(response, '"');
    if (!val) return RCI_MARK_ABSENT;
    val++;
    const char *end = strchr(val, '"');
    if (!end) return RCI_MARK_ABSENT;

    if (val[0] == '0' && (val[1] == 'x' || val[1] == 'X'))
        val += 2;
    int n = (int)(end - val);
    if (n <= 0) return RCI_MARK_ABSENT;
    if (n > mark_size - 1) n = mark_size - 1;
    memcpy(mark, val, n);
    mark[n] = '\0';

    LOG_DEBUG("RCI policy: %s mark=0x%s", name, mark);
    return RCI_MARK_OK;
}

#define RCI_POLICY_CREATE_FMT "{\"ip\":{\"policy\":{\"%s\":{\"description\":\"%s\"}}}},"

int rci_create_policies(const char (*names)[64], int count) {
    if (count == 0) return 0;

    char body[MAX_POLICY_ORDER * (sizeof(RCI_POLICY_CREATE_FMT) + 2 * 64) + 64];
    int off = snprintf(body, sizeof(body), "[");
    for (int i = 0; i < count; i++) {
        off += snprintf(body + off, sizeof(body) - off,
                        RCI_POLICY_CREATE_FMT, names[i], names[i]);
    }
    off += snprintf(body + off, sizeof(body) - off,
                    "{\"system\":{\"configuration\":{\"save\":true}}}]");

    char response[4096];
    int ret = rci_request("POST", "/rci/", body, off, response, sizeof(response));
    if (ret == RCI_ERR_DENIED) {
        LOG_ERROR("RCI denied policy creation: access token required or rejected");
        return -1;
    }
    if (ret < 0) {
        LOG_WARN("Failed to create policies via RCI");
        return -1;
    }
    LOG_INFO("Policy creation commands executed");
    return 0;
}
