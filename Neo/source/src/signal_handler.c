#include "../include/signal_handler.h"
#include "../include/log.h"
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <stdint.h>

int signal_mgr_init(signal_mgr_t *m) {
    m->sig_fd = -1;
    m->timer_fd = -1;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGUSR1);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        LOG_ERROR("sigprocmask failed");
        return -1;
    }

    m->sig_fd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (m->sig_fd < 0) {
        LOG_ERROR("signalfd failed");
        return -1;
    }

    m->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (m->timer_fd < 0) {
        LOG_ERROR("timerfd_create failed");
        close(m->sig_fd);
        m->sig_fd = -1;
        return -1;
    }

    return 0;
}

void signal_mgr_close(signal_mgr_t *m) {
    if (m->timer_fd >= 0) { close(m->timer_fd); m->timer_fd = -1; }
    if (m->sig_fd   >= 0) { close(m->sig_fd);   m->sig_fd   = -1; }
}

void signal_mgr_arm_timer(signal_mgr_t *m, int seconds) {
    struct itimerspec ts;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;
    ts.it_value.tv_sec = seconds;
    ts.it_value.tv_nsec = 0;
    timerfd_settime(m->timer_fd, 0, &ts, NULL);
}

int signal_mgr_read_timer(signal_mgr_t *m) {
    uint64_t expirations;
    ssize_t s = read(m->timer_fd, &expirations, sizeof(expirations));
    if (s != sizeof(expirations)) return -1;
    return (int)expirations;
}
