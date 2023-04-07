#ifndef CONFIG_H
#define CONFIG_H

#include "address.h"
#include "list.h"

typedef enum {
	CHIPVPN_DEVICE_BIND     = (1 << 0),
	CHIPVPN_DEVICE_POSTUP   = (1 << 1),
	CHIPVPN_DEVICE_POSTDOWN = (1 << 2)
} chipvpn_config_flag_e;

typedef struct {
	chipvpn_config_flag_e flag;
	chipvpn_address_t address;
	chipvpn_address_t bind;
	char postup[1024];
	char postdown[1024];
	List peers;
} chipvpn_config_t;

typedef enum {
	CONFIG_SECTION_NONE,
	CONFIG_SECTION_INTERFACE,
	CONFIG_SECTION_PEER
} chipvpn_config_section_e;

char   *chipvpn_config_read_file(const char *file);
void    chipvpn_config_load(chipvpn_config_t *config, char *file);

#endif