#ifndef CONFIG_H
#define CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "chipvpn.h"

typedef enum {
	COMMAND_DEVICE_SECTION,
	COMMAND_PEER_SECTION
} chipvpn_command_section_e;

void chipvpn_config_command(chipvpn_t *vpn, const char *command);

#ifdef __cplusplus
}
#endif

#endif
