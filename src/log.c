#include "log.h"
#include <stdarg.h>
#include <stdio.h>

void chipvpn_log_append(char* format, ...) {
	char buffer[1024];

	va_list args;
	va_start(args, format);
	vsprintf(buffer, format, args);
	va_end(args);

	fprintf(stdout, "%s", buffer);

}