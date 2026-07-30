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

#define RCI_RAW_MAX    32768
#define RCI_HTTP_FAIL  (-2)

static char g_rci_token[MAX_RCI_TOKEN];

void rci_set_token(const char *token) {
    int j = 0;
    if (token) {
        for (int i = 0; token[i] && j < MAX_RCI_TOKEN - 1; i++) {
            unsigned char ch = (unsigned char)token[i];
            if (ch <= 0x20 || ch >= 0x7f) break;
            g_rci_token[j++] = (char)ch;
        }
    }
    g_rci_token[j] = '\0';
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

static int rci_request(const char *method, const char *path,
                       const char *body, int body_len,
                       char *response, int response_max) {
    int fd = rci_connect();
    if (fd < 0) {
        LOG_ERROR("RCI connect failed: %s", strerror(errno));
        return -1;
    }

    char tkn_hdr[MAX_RCI_TOKEN + 24];
    if (g_rci_token[0])
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
    if (!body_start) return -1;
    body_start += 4;

    if (strncmp(raw, "HTTP/", 5) != 0) return -1;
    char *status = strchr(raw, ' ');
    if (!status || atoi(status + 1) != 200)
        return RCI_HTTP_FAIL;

    int response_len = total - (int)(body_start - raw);
    if (response_len > response_max - 1) response_len = response_max - 1;
    memcpy(response, body_start, response_len);
    response[response_len] = '\0';

    return response_len;
}

int rci_get_policy_mark(const char *name, char *mark, int mark_size) {
    char path[160];
    snprintf(path, sizeof(path), "/rci/show/ip/policy/%s/mark", name);

    char response[256];
    int len = rci_request("GET", path, NULL, 0, response, sizeof(response));
    if (len == -1) return -1;
    if (len < 0) return 0;

    const char *val = strchr(response, '"');
    if (!val) return 0;
    val++;
    const char *end = strchr(val, '"');
    if (!end) return 0;

    if (val[0] == '0' && (val[1] == 'x' || val[1] == 'X'))
        val += 2;
    int n = (int)(end - val);
    if (n <= 0) return 0;
    if (n > mark_size - 1) n = mark_size - 1;
    memcpy(mark, val, n);
    mark[n] = '\0';

    LOG_DEBUG("RCI policy: %s mark=0x%s", name, mark);
    return 1;
}

int rci_create_policies(const char (*names)[64], int count) {
    if (count == 0) return 0;

    char body[8192];
    int off = snprintf(body, sizeof(body), "[");
    for (int i = 0; i < count; i++) {
        off += snprintf(body + off, sizeof(body) - off,
                        "{\"parse\":\"ip policy %s\"},", names[i]);
    }
    off += snprintf(body + off, sizeof(body) - off,
                    "{\"system\":{\"configuration\":{\"save\":true}}}]");

    char response[4096];
    int ret = rci_request("POST", "/rci/", body, off, response, sizeof(response));
    if (ret < 0) {
        LOG_WARN("Failed to create policies via RCI");
        return -1;
    }
    LOG_INFO("Policy creation commands executed");
    return 0;
}
