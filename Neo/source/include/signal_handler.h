#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

typedef struct {
    int sig_fd;
    int timer_fd;
} signal_mgr_t;

int  signal_mgr_init(signal_mgr_t *m);
void signal_mgr_close(signal_mgr_t *m);
void signal_mgr_arm_timer(signal_mgr_t *m, int milliseconds);
int  signal_mgr_read_timer(signal_mgr_t *m);

#endif
