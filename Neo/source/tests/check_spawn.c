#include "../include/util.h"
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>

static long elapsed_ms(const struct timespec *t0) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000 + (t.tv_nsec - t0->tv_nsec) / 1000000;
}

static int sh(const char *script, char *out, size_t out_size, long *ms) {
    char *argv[] = {"sh", "-c", (char *)script, NULL};
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = run_command_output("sh", argv, out, out_size);
    *ms = elapsed_ms(&t0);
    return rc;
}

static int sh_stdin(const char *script, const char *in, size_t in_len, long *ms) {
    char *argv[] = {"sh", "-c", (char *)script, NULL};
    char out[64];
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = run_command_stdin("sh", argv, in, in_len, out, sizeof(out));
    *ms = elapsed_ms(&t0);
    return rc;
}

int main(void) {
    char out[64];
    long ms;

    sigset_t all;
    sigfillset(&all);
    sigprocmask(SIG_SETMASK, &all, NULL);
    signal(SIGPIPE, SIG_IGN);
    assert(sh("kill -PIPE $$; exit 0", out, sizeof(out), &ms) == -1);

    assert(sh("printf hello; echo err >&2", out, sizeof(out), &ms) == 0);
    assert(strcmp(out, "helloerr\n") == 0);
    assert(sh("exit 3", out, sizeof(out), &ms) == 3 && out[0] == '\0');
    assert(sh("head -c 200 /dev/zero | tr '\\0' x", out, sizeof(out), &ms) == -1);
    assert(strlen(out) == sizeof(out) - 1);

    char *argv[] = {"hrneo-no-such-command", NULL};
    assert(run_command_output(argv[0], argv, out, sizeof(out)) == 127);

    assert(sh("sleep 5", out, sizeof(out), &ms) == -1);
    assert(ms >= CHILD_DEADLINE_MS - 1 && ms < CHILD_DEADLINE_MS + 1000);
    assert(sh("exec >&- 2>&-; sleep 5", out, sizeof(out), &ms) == -1);
    assert(ms >= CHILD_DEADLINE_MS - 1 && ms < CHILD_DEADLINE_MS + 1000);

    static char big[256 * 1024];
    memset(big, 'x', sizeof(big));
    assert(sh_stdin("test \"$(wc -c)\" -eq 262144", big, sizeof(big), &ms) == 0);
    assert(sh_stdin("cat >/dev/null; exit 4", "", 0, &ms) == 4);
    assert(sh_stdin("sleep 5", big, sizeof(big), &ms) == -1);
    assert(ms >= CHILD_DEADLINE_MS - 1 && ms < CHILD_DEADLINE_MS + 1000);

    char *cat_argv[] = {"sh", "-c", "cat; echo err >&2; exit 2", NULL};
    assert(run_command_stdin("sh", cat_argv, "abc", 3, out, sizeof(out)) == 2);
    assert(strcmp(out, "abcerr\n") == 0);

    puts("check_spawn: OK");
    return 0;
}
