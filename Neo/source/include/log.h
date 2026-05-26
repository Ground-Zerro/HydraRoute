#ifndef LOG_H
#define LOG_H

#include "hrneo.h"

extern int log_enabled;

int log_setup(const config_t *cfg);
void log_close(void);
void log_write(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#define LOG_INFO(fmt, ...)      do { if (log_enabled) log_write("[INFO] " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_DEBUG(fmt, ...)     do { if (log_enabled) log_write("[DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_MATCH(fmt, ...)     do { if (log_enabled) log_write("[MATCH] " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_PROCESSED(fmt, ...) do { if (log_enabled) log_write("[PROCESSED] " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_FILTERED(fmt, ...)  do { if (log_enabled) log_write("[FILTERED] " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_WARN(fmt, ...)      log_write("[WARN] " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)     log_write("[ERROR] " fmt "\n", ##__VA_ARGS__)

#endif
