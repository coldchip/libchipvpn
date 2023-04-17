#ifndef CHIPVPN_H
#define CHIPVPN_H

#include <stdbool.h>
#include <stdint.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

void chipvpn_setup(char *file);
void chipvpn_init(char *file);
void chipvpn_loop();
void chipvpn_print_stats();
void chipvpn_cleanup();
void chipvpn_exit(int type);

void chipvpn_log(const char *format, ...);
void chipvpn_error(const char *format, ...);
uint32_t chipvpn_get_time();

#endif