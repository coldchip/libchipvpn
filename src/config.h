#ifndef CONFIG_H
#define CONFIG_H

#include "address.h"
#include "list.h"

typedef struct {
	chipvpn_address_t address;
	chipvpn_address_t bind;
	bool has_bind;
	char postup[1024];
	bool has_postup;
	char postdown[1024];
	bool has_postdown;
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