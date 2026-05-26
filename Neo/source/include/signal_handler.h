#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

/* Bundled signalfd + debounce-timer manager. Owns the two fds used by the
 * main epoll loop: sig_fd (SIGINT/SIGTERM/SIGUSR1 via signalfd) and timer_fd
 * (CLOCK_MONOTONIC timerfd that debounces SIGUSR1). */
typedef struct {
    int sig_fd;
    int timer_fd;
} signal_mgr_t;

int  signal_mgr_init(signal_mgr_t *m);
void signal_mgr_close(signal_mgr_t *m);
void signal_mgr_arm_timer(signal_mgr_t *m, int seconds);
int  signal_mgr_read_timer(signal_mgr_t *m);

#endif
