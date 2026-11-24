#include "log.h"
#include "util.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ANSI_RESET  "\x1b[0m"
#define ANSI_DIM    "\x1b[90m"
#define ANSI_RED    "\x1b[31m"
#define ANSI_BRED   "\x1b[1;31m"
#define ANSI_BG_RED "\x1b[1;37;41m"
#define ANSI_BCYN   "\x1b[1;36m"
#define ANSI_YELLOW  "\x1b[33m"

int chipvpn_log_current_level = CHIPVPN_LOG_INFO;

static struct {
	int fd;
	int color;
	int fd_is_tty;
	chipvpn_log_cb_t cb;
	void *userdata;
} g_log = {
	.fd = STDOUT_FILENO,
	.color = -1,
	.fd_is_tty = -1,
	.cb = NULL,
	.userdata = NULL
};

static const char *const g_level_tags[] = {
	[CHIPVPN_LOG_NONE]  = "",
	[CHIPVPN_LOG_FATAL] = "FATAL",
	[CHIPVPN_LOG_ERROR] = "ERROR",
	[CHIPVPN_LOG_INFO]  = "INFO",
	[CHIPVPN_LOG_WARN]  = "WARN"
};

static const char *const g_level_colors[] = {
	[CHIPVPN_LOG_NONE]  = "",
	[CHIPVPN_LOG_FATAL] = ANSI_BG_RED,
	[CHIPVPN_LOG_ERROR] = ANSI_BRED,
	[CHIPVPN_LOG_INFO]  = ANSI_BCYN,
	[CHIPVPN_LOG_WARN]  = ANSI_YELLOW
};

static bool chipvpn_log_should_color(void) {
	if(g_log.color >= 0) {
		return g_log.color != 0;
	}
	if(g_log.cb || g_log.fd < 0) {
		return false;
	}
	if(g_log.fd_is_tty < 0) {
		g_log.fd_is_tty = isatty(g_log.fd) ? 1 : 0;
	}
	return g_log.fd_is_tty != 0;
}

void chipvpn_log_set_level(int level) {
	chipvpn_log_current_level = level;
}

void chipvpn_log_set_fd(int fd) {
	g_log.fd = fd;
	g_log.fd_is_tty = (fd >= 0) ? (isatty(fd) ? 1 : 0) : 0;
}

void chipvpn_log_set_color(bool enable) {
	g_log.color = enable ? 1 : 0;
}

void chipvpn_log_set_callback(chipvpn_log_cb_t cb, void *userdata) {
	g_log.cb = cb;
	g_log.userdata = userdata;
}

void chipvpn_log_write(int level, const char *fmt, ...) {
	char buf[512];
	const bool use_color = chipvpn_log_should_color();
	const bool color_body = use_color &&
		(level == CHIPVPN_LOG_FATAL || level == CHIPVPN_LOG_ERROR || level == CHIPVPN_LOG_WARN);

	const char *suffix = color_body ? (ANSI_RESET "\n") : "\n";
	const size_t suffix_len = color_body ? (sizeof(ANSI_RESET "\n") - 1) : 1;
	const size_t max_text = sizeof(buf) - suffix_len - 1; /* room for suffix + '\0' */
	size_t pos = 0;

	const bool valid_lvl = (level >= CHIPVPN_LOG_FATAL && level <= CHIPVPN_LOG_INFO);
	const char *tag = valid_lvl ? g_level_tags[level] : "LOG";
	const unsigned long long ts = chipvpn_get_realtime() / 1000ULL;

	int n;
	if(use_color) {
		const char *tag_color = valid_lvl ? g_level_colors[level] : "";
		const char *body_color = "";
		if(level == CHIPVPN_LOG_FATAL) {
			body_color = ANSI_BRED;
		} else if(level == CHIPVPN_LOG_ERROR) {
			body_color = ANSI_RED;
		} else if(level == CHIPVPN_LOG_WARN) {
			body_color = ANSI_YELLOW;
		}
		n = snprintf(buf, max_text + 1, ANSI_DIM "[%llu]" ANSI_RESET " %s[%s]" ANSI_RESET " %s", ts, tag_color, tag, body_color);
	} else {
		n = snprintf(buf, max_text + 1, "[%llu] [%s] ", ts, tag);
	}

	if(n > 0) {
		pos = ((size_t)n < max_text) ? (size_t)n : max_text;
	}

	if(pos < max_text) {
		va_list ap;
		va_start(ap, fmt);
		n = vsnprintf(buf + pos, (max_text - pos) + 1, fmt, ap);
		va_end(ap);

		if (n > 0) {
			size_t rem = max_text - pos;
			pos += ((size_t)n < rem) ? (size_t)n : rem;
		}
	}

	if(pos > 0 && buf[pos - 1] == '\n') {
		pos--;
	}

	memcpy(buf + pos, suffix, suffix_len);
	pos += suffix_len;
	buf[pos] = '\0';

	if(g_log.cb) {
		g_log.cb(level, buf, pos, g_log.userdata);
	} else if(g_log.fd >= 0) {
		ssize_t ignored = write(g_log.fd, buf, pos);
		(void)ignored;
	}
}