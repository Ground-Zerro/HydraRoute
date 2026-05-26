#include "../include/rci.h"
#include "../include/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int rci_save_config(rci_client_t *c);

int rci_client_init(rci_client_t *c) {
    c->raw_buf = malloc(RCI_MAX_RESPONSE + 4096);
    c->response_buf = malloc(RCI_MAX_RESPONSE);
    if (!c->raw_buf || !c->response_buf) {
        free(c->raw_buf);
        free(c->response_buf);
        c->raw_buf = NULL;
        c->response_buf = NULL;
        LOG_ERROR("RCI client: failed to allocate buffers");
        return -1;
    }
    return 0;
}

void rci_client_close(rci_client_t *c) {
    free(c->raw_buf);
    free(c->response_buf);
    c->raw_buf = NULL;
    c->response_buf = NULL;
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

static int rci_request(rci_client_t *c,
                       const char *method, const char *path,
                       const char *body, int body_len,
                       char *response, int response_max) {
    int fd = rci_connect();
    if (fd < 0) {
        LOG_ERROR("RCI connect failed: %s", strerror(errno));
        return -1;
    }

    char header[512];
    int hlen;
    if (body && body_len > 0) {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "\r\n",
            method, path, body_len);
    } else {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.0\r\n"
            "Host: localhost\r\n"
            "\r\n",
            method, path);
    }

    if (send(fd, header, hlen, 0) != hlen) {
        close(fd);
        return -1;
    }

    if (body && body_len > 0) {
        int total = 0;
        while (total < body_len) {
            int n = send(fd, body + total, body_len - total, 0);
            if (n <= 0) { close(fd); return -1; }
            total += n;
        }
    }

    char *raw = c->raw_buf;
    int raw_capacity = RCI_MAX_RESPONSE + 4096;

    int total = 0;
    int max_raw = raw_capacity - 1;
    while (total < max_raw) {
        int n = recv(fd, raw + total, max_raw - total, 0);
        if (n <= 0) break;
        total += n;
    }
    raw[total] = '\0';
    close(fd);

    char *body_start = strstr(raw, "\r\n\r\n");
    if (!body_start) return -1;
    body_start += 4;

    if (strncmp(raw, "HTTP/", 5) != 0) return -1;
    char *status = strchr(raw, ' ');
    if (!status || atoi(status + 1) != 200) {
        LOG_ERROR("RCI response status: %d", status ? atoi(status + 1) : 0);
        return -1;
    }

    int response_len = total - (int)(body_start - raw);
    if (response_len > response_max - 1) response_len = response_max - 1;
    memcpy(response, body_start, response_len);
    response[response_len] = '\0';

    return response_len;
}

static const char *find_matching_brace(const char *open_brace) {
    int depth = 0;
    int in_string = 0;
    for (const char *c = open_brace; *c; c++) {
        if (*c == '"' && (c == open_brace || *(c - 1) != '\\')) {
            in_string = !in_string;
            continue;
        }
        if (in_string) continue;
        if (*c == '{') depth++;
        else if (*c == '}') {
            depth--;
            if (depth == 0) return c;
        }
    }
    return NULL;
}

static int rci_get_policies(rci_client_t *c, policy_mark_t *policies, int max_policies) {
    char *response = c->response_buf;

    int len = rci_request(c, "GET", "/rci/show/ip/policy/",
                          NULL, 0, response, RCI_MAX_RESPONSE);
    if (len <= 0) return -1;

    int count = 0;

    const char *root_brace = strchr(response, '{');
    if (!root_brace) return 0;
    const char *p = root_brace + 1;

    while (*p && count < max_policies) {
        const char *key_start = strchr(p, '"');
        if (!key_start) break;
        key_start++;
        const char *key_end = strchr(key_start, '"');
        if (!key_end) break;

        int key_len = (int)(key_end - key_start);

        const char *brace = strchr(key_end + 1, '{');
        if (!brace) break;
        const char *end_brace = find_matching_brace(brace);
        if (!end_brace) break;

        if (key_len <= 0 || key_len >= MAX_POLICY_NAME) {
            p = end_brace + 1;
            continue;
        }

        const char *mark_key = strstr(brace, "\"mark\"");
        if (!mark_key || mark_key > end_brace) {
            p = end_brace + 1;
            continue;
        }

        const char *colon = strchr(mark_key + 6, ':');
        if (!colon || colon > end_brace) { p = end_brace + 1; continue; }

        const char *val_start = strchr(colon, '"');
        if (!val_start || val_start > end_brace) { p = end_brace + 1; continue; }
        val_start++;
        const char *val_end = strchr(val_start, '"');
        if (!val_end || val_end > end_brace) { p = end_brace + 1; continue; }

        memcpy(policies[count].name, key_start, key_len);
        policies[count].name[key_len] = '\0';

        const char *mark_val = val_start;
        if (mark_val[0] == '0' && (mark_val[1] == 'x' || mark_val[1] == 'X'))
            mark_val += 2;
        int mark_len = (int)(val_end - mark_val);
        if (mark_len >= 16) mark_len = 15;
        memcpy(policies[count].mark, mark_val, mark_len);
        policies[count].mark[mark_len] = '\0';

        LOG_DEBUG("RCI policy: %s mark=0x%s", policies[count].name, policies[count].mark);
        count++;
        p = end_brace + 1;
    }

    return count;
}

int rci_get_policies_with_retry(rci_client_t *c, policy_mark_t *policies, int max_policies) {
    for (int attempt = 0; attempt < POLICY_API_MAX_RETRIES; attempt++) {
        int count = rci_get_policies(c, policies, max_policies);
        if (count >= 0) return count;
        if (attempt < POLICY_API_MAX_RETRIES - 1) {
            LOG_WARN("Policy API attempt %d/%d failed, retrying in %ds...",
                     attempt + 1, POLICY_API_MAX_RETRIES, POLICY_API_RETRY_DELAY);
            sleep(POLICY_API_RETRY_DELAY);
        }
    }
    LOG_ERROR("Policy API failed after %d attempts", POLICY_API_MAX_RETRIES);
    return -1;
}

int rci_create_policies(rci_client_t *c, const char (*names)[64], int count) {
    if (count == 0) return 0;

    char body[4096];
    int off = 0;
    off += snprintf(body + off, sizeof(body) - off, "[");
    for (int i = 0; i < count; i++) {
        if (i > 0) off += snprintf(body + off, sizeof(body) - off, ",");
        off += snprintf(body + off, sizeof(body) - off,
                        "{\"parse\":\"ip policy %s\"}", names[i]);
    }
    off += snprintf(body + off, sizeof(body) - off, "]");

    char response[1024];
    int ret = rci_request(c, "POST", "/rci/", body, off, response, sizeof(response));
    if (ret < 0) {
        LOG_WARN("Failed to create policies via RCI");
    } else {
        LOG_INFO("Policy creation commands executed");
    }

    rci_save_config(c);
    return ret >= 0 ? 0 : -1;
}

static int rci_save_config(rci_client_t *c) {
    const char *body = "{\"system\":{\"configuration\":{\"save\":true}}}";
    char response[1024];
    int ret = rci_request(c, "POST", "/rci/", body, strlen(body), response, sizeof(response));
    if (ret < 0) {
        LOG_ERROR("Failed to save RCI configuration");
    }
    return ret >= 0 ? 0 : -1;
}
