#ifndef CONFIG_H
#define CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "chipvpn.h"

void chipvpn_config_command(chipvpn_t *vpn, char *command);

#ifdef __cplusplus
}
#endif

#endif