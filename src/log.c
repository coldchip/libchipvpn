#include "log.h"
#include <stdarg.h>
#include <stdio.h>

/*
 * Append a formatted message to stdout.
 * Uses vsnprintf to guard against buffer overflows.
 */
void chipvpn_log_append(const char *format, ...) {
	char buffer[1024];

	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	fputs(buffer, stdout);
	fflush(stdout);
}
