#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>

char*        str_replace(const char* s, const char* oldW, const char* newW);
bool         get_gateway(char *ip);

#endif