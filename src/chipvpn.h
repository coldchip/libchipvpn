#ifndef CHIPVPN_H
#define CHIPVPN_H

#include <stdbool.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

void chipvpn_setup(bool server);
void chipvpn_init(bool server);
void chipvpn_loop();
void chipvpn_cleanup();
void chipvpn_exit(int type);

void chipvpn_log(const char *format, ...);
void chipvpn_error(const char *format, ...);

#endif