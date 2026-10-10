#include "../include/signal_handler.h"
#include "../include/log.h"
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

int signal_mgr_init(signal_mgr_t *m) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGUSR1);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        LOG_ERROR("sigprocmask failed");
        m->sig_fd = -1;
        return -1;
    }

    m->sig_fd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (m->sig_fd < 0) {
        LOG_ERROR("signalfd failed");
        return -1;
    }
    return 0;
}

void signal_mgr_close(signal_mgr_t *m) {
    if (m->sig_fd >= 0) { close(m->sig_fd); m->sig_fd = -1; }
}
