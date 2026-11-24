#ifndef LOG_H
#define LOG_H

#include <stdbool.h>
#include <stddef.h>

enum {
	CHIPVPN_LOG_NONE  = 0,
	CHIPVPN_LOG_FATAL = 1,
	CHIPVPN_LOG_ERROR = 2,
	CHIPVPN_LOG_WARN  = 3,
	CHIPVPN_LOG_INFO  = 4
};

typedef void (*chipvpn_log_cb_t)(int level, const char *msg, size_t len, void *userdata);

extern int chipvpn_log_current_level;

#ifndef CHIPVPN_LOG_MAX_LEVEL
#define CHIPVPN_LOG_MAX_LEVEL CHIPVPN_LOG_INFO
#endif

void chipvpn_log_set_level(int level);
void chipvpn_log_set_fd(int fd);
void chipvpn_log_set_color(bool enable);
void chipvpn_log_set_callback(chipvpn_log_cb_t cb, void *userdata);

void chipvpn_log_write(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#define CHIPVPN_LOG(lvl, ...)                                            \
	do {                                                                 \
		if ((lvl) <= CHIPVPN_LOG_MAX_LEVEL &&                            \
		    (lvl) <= chipvpn_log_current_level) {                        \
			chipvpn_log_write((lvl), __VA_ARGS__);                       \
		}                                                                \
	} while (0)

#define LOG_FATAL(...) CHIPVPN_LOG(CHIPVPN_LOG_FATAL, __VA_ARGS__)
#define LOG_ERR(...)   CHIPVPN_LOG(CHIPVPN_LOG_ERROR, __VA_ARGS__)
#define LOG_INFO(...)  CHIPVPN_LOG(CHIPVPN_LOG_INFO,  __VA_ARGS__)
#define LOG_WARN(...)  CHIPVPN_LOG(CHIPVPN_LOG_WARN, __VA_ARGS__)

#endif