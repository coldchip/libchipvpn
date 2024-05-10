#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>

char        *strdup(const char *s);
char        *str_replace(const char* s, const char* oldW, const char* newW);
bool         get_gateway(char *ip, char *dev);
char        *chipvpn_format_bytes(uint64_t bytes);
bool         chipvpn_secure_random(char *buf, int size);
uint64_t     chipvpn_get_time();

#endif