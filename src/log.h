#ifndef LOG_H
#define LOG_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdarg.h>

void chipvpn_log_append(const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
