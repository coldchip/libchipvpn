#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>

char        *strdup(const char *s);
char        *str_replace(const char* s, const char* oldW, const char* newW);
bool         get_gateway(char *ip);
char        *chipvpn_format_bytes(uint64_t bytes);
uint64_t     chipvpn_get_time();

#endif