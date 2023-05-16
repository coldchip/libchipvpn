#ifndef CONFIG_H
#define CONFIG_H

#include "address.h"
#include "list.h"

typedef enum {
	CHIPVPN_DEVICE_BIND     = (1 << 0),
	CHIPVPN_DEVICE_POSTUP   = (1 << 1),
	CHIPVPN_DEVICE_POSTDOWN = (1 << 2),
	CHIPVPN_DEVICE_NAME     = (1 << 3)
} chipvpn_device_flag_e;

typedef struct {
	chipvpn_device_flag_e flag;
	chipvpn_address_t address;
	chipvpn_address_t bind;
	int mtu;
	char *name;
	char *postup;
	char *postdown;
	chipvpn_list_t peers;
} chipvpn_device_t;

chipvpn_device_t     *chipvpn_device_create(char *file);
bool                  chipvpn_device_reload_config(chipvpn_device_t *device, char *file);
int                   chipvpn_device_parse_handler(void* user, const char* section, const char* name, const char* value);
void                  chipvpn_device_free(chipvpn_device_t *device);

#endif