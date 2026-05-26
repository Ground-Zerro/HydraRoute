#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

int log_enabled = 0;
static int log_syslog = 0;
static FILE *log_fp = NULL;

void log_write(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (log_syslog) {
        vsyslog(LOG_INFO, fmt, args);
    } else {
        FILE *out = log_fp ? log_fp : stderr;
        vfprintf(out, fmt, args);
        fflush(out);
    }
    va_end(args);
}

int log_setup(const config_t *cfg) {
    if (strcmp(cfg->log_level, "console") == 0) {
        log_fp = stdout;
        log_enabled = 1;
    } else if (strcmp(cfg->log_level, "file") == 0) {
        if (cfg->log_file_path[0] == '\0') {
            log_fp = NULL;
            log_enabled = 0;
            return 0;
        }
        char dir[MAX_PATH_LEN];
        strncpy(dir, cfg->log_file_path, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = '\0';
        char *last_slash = strrchr(dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            mkdir_p(dir, 0755);
        }
        log_fp = fopen(cfg->log_file_path, "a");
        if (!log_fp) return -1;
        log_enabled = 1;
    } else if (strcmp(cfg->log_level, "syslog") == 0) {
        openlog("hrneo", LOG_PID | LOG_NDELAY, LOG_DAEMON);
        log_syslog = 1;
        log_enabled = 1;
    } else {
        log_fp = NULL;
        log_enabled = 0;
    }
    return 0;
}

void log_close(void) {
    if (log_fp && log_fp != stdout && log_fp != stderr) {
        fclose(log_fp);
    }
    log_fp = NULL;
    if (log_syslog) {
        closelog();
        log_syslog = 0;
    }
    log_enabled = 0;
}
