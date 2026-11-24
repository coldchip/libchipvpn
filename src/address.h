#ifndef ADDRESS_H
#define ADDRESS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>

enum {
	CHIPVPN_ADDRESS_NONE = 0,
	CHIPVPN_ADDRESS_IPV4 = 4,
	CHIPVPN_ADDRESS_IPV6 = 6
};

typedef struct {
	int type;
	union {
		uint8_t ipv6[16];
		uint32_t ipv4;
	};
	uint16_t port;
	uint8_t prefix;
} chipvpn_address_t;

bool           chipvpn_address_set_ip(chipvpn_address_t *address, const char *ip);
bool           chipvpn_address_network_match(chipvpn_address_t *network, chipvpn_address_t *address);
bool           chipvpn_address_endpoint_match(chipvpn_address_t *left, chipvpn_address_t *right);
const char    *chipvpn_address_to_char(chipvpn_address_t *address);     

#ifdef __cplusplus
}
#endif

#endif