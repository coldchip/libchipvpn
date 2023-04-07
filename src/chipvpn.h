#ifndef CHIPVPN_H
#define CHIPVPN_H

#include <stdbool.h>
#include "config.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define CHIPVPN_MTU 1420

void chipvpn_setup(chipvpn_config_t *config);
void chipvpn_init();
void chipvpn_loop();
void chipvpn_cleanup();
void chipvpn_exit(int type);

void chipvpn_log(const char *format, ...);
void chipvpn_error(const char *format, ...);

#endif