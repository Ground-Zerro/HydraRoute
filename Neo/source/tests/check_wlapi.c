#include "../include/watchlist.h"
#include "../include/watchlist_api.h"
#include "../include/util.h"
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCK_PATH "build/check_wlapi.sock"
#define BULK_KEYS 20000

static char big[1 << 21];

static int dial(void) {
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCK_PATH);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(fd >= 0);
    assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    return fd;
}

static void say(int fd, const char *s) {
    assert(send(fd, s, strlen(s), MSG_NOSIGNAL) == (ssize_t)strlen(s));
}

static size_t drain(int fd, char *buf, size_t cap) {
    size_t len = 0;
    ssize_t n;
    while ((n = recv(fd, buf + len, cap - 1 - len, 0)) > 0) len += (size_t)n;
    buf[len] = '\0';
    close(fd);
    return len;
}

static void read_line(int fd, char *buf, size_t cap) {
    size_t len = 0;
    struct pollfd p = { .fd = fd, .events = POLLIN };
    while (len == 0 || buf[len - 1] != '\n') {
        assert(poll(&p, 1, 1000) == 1);
        ssize_t n = recv(fd, buf + len, cap - 1 - len, 0);
        assert(n > 0);
        len += (size_t)n;
    }
    buf[len] = '\0';
}

static void expect_reply(int fd, const char *req, const char *reply) {
    char buf[512];
    say(fd, req);
    read_line(fd, buf, sizeof(buf));
    assert(strcmp(buf, reply) == 0);
}

static domain_hashtable_t *load(void) {
    domain_hashtable_t *ht = ht_create();
    ht_insert(ht, "ru", 2, "RU");
    ht_insert(ht, "google.ru", 9, "HydraRoute");
    ht_insert(ht, "telegram.org", 12, "HydraRoute");
    for (int i = 0; i < BULK_KEYS; i++) {
        char key[32];
        int n = snprintf(key, sizeof(key), "k%05d.example", i);
        ht_insert(ht, key, (size_t)n, "HydraRoute");
    }
    const char order[][64] = { "RU" };
    char names[MAX_TARGETS][64];
    int count = get_unique_names(ht, names, MAX_TARGETS);
    sort_policies(names, count, order, 1);
    ht_rank_targets(ht, (const char (*)[64])names, count);
    return ht;
}

static void check_pipeline(void) {
    int fd = dial();
    char name[300];
    memset(name, 'a', 254);
    name[254] = '\0';
    say(fd, "MATCH Mail.Google.RU.\nMATCH example.org\nMATCH telegram.org\nMATCH ru\r\n"
            "MATCH \nBOGUS\nMATCH ");
    say(fd, name);
    say(fd, "\n");
    shutdown(fd, SHUT_WR);
    char buf[1024];
    drain(fd, buf, sizeof(buf));
    assert(strcmp(buf, "OK RU 0 ru\nNO\nOK HydraRoute 1 telegram.org\nOK RU 0 ru\n"
                       "ERR name\nERR command\nERR name\n") == 0);
}

static void check_dump_does_not_block_match(void) {
    int dumper = dial();
    say(dumper, "DUMP\n");
    usleep(100000);

    int fd = dial();
    expect_reply(fd, "MATCH k00042.example\n", "OK HydraRoute 1 k00042.example\n");
    close(fd);

    shutdown(dumper, SHUT_WR);
    size_t len = drain(dumper, big, sizeof(big));
    assert(len > 0 && big[len - 1] == '\n');
    assert(strncmp(big, "T 0 RU\nT 1 HydraRoute\nK ", 24) == 0);
    assert(strstr(big, "\nK ru 0\n") && strstr(big, "\nK google.ru 1\n"));

    int keys = 0;
    for (char *line = big; *line; line = strchr(line, '\n') + 1) {
        if (line[0] == 'K') keys++;
    }
    assert(keys == BULK_KEYS + 3);
    char end[32];
    snprintf(end, sizeof(end), "\nEND %d\n", keys);
    assert(strcmp(big + len - strlen(end), end) == 0);
}

static void check_client_limit(void) {
    int fds[4];
    for (int i = 0; i < 4; i++) {
        fds[i] = dial();
        expect_reply(fds[i], "MATCH ru\n", "OK RU 0 ru\n");
    }
    char buf[64];
    drain(dial(), buf, sizeof(buf));
    assert(strcmp(buf, "ERR busy\n") == 0);
    for (int i = 0; i < 4; i++) close(fds[i]);

    for (int attempt = 0;; attempt++) {
        assert(attempt < 100);
        int fd = dial();
        say(fd, "MATCH ru\n");
        shutdown(fd, SHUT_WR);
        drain(fd, buf, sizeof(buf));
        if (strcmp(buf, "OK RU 0 ru\n") == 0) break;
        usleep(10000);
    }
}

static void check_cli_exit_codes(void) {
    fflush(stdout);
    int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
    int null_fd = open("/dev/null", O_WRONLY);
    assert(null_fd >= 0);
    dup2(null_fd, STDOUT_FILENO);
    dup2(null_fd, STDERR_FILENO);
    close(null_fd);
    assert(wlapi_request(SOCK_PATH, "MATCH", "www.Google.RU") == 0);
    assert(wlapi_request(SOCK_PATH, "MATCH", "example.org") == 1);
    assert(wlapi_request(SOCK_PATH, "BOGUS", NULL) == 2);
    assert(wlapi_request(SOCK_PATH, "DUMP", NULL) == 0);
    assert(wlapi_request("build/absent.sock", "DUMP", NULL) == 2);
    fflush(stdout);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
}

int main(void) {
    domain_hashtable_t *ht = load();
    assert(wlapi_start(SOCK_PATH, ht) == 0);

    check_pipeline();
    check_dump_does_not_block_match();
    check_client_limit();
    check_cli_exit_codes();

    wlapi_stop();
    assert(access(SOCK_PATH, F_OK) != 0);
    ht_destroy(ht);
    puts("check_wlapi: OK");
    return 0;
}
