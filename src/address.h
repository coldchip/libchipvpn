#ifndef ADDRESS_H
#define ADDRESS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/un.h>

typedef enum {
	CHIPVPN_ADDRESS_IPV4,
	CHIPVPN_ADDRESS_IPV6
} chipvpn_address_type_e;

typedef struct {
	chipvpn_address_type_e type;
	union {
		uint32_t ipv4;
		uint8_t ipv6[16];
	};
	uint16_t port;
	uint8_t prefix;
} chipvpn_address_t;

bool           chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip);
bool           chipvpn_address_cidr_match(chipvpn_address_t *net, chipvpn_address_t *addr);
char          *chipvpn_address_to_char(chipvpn_address_t *addr);     

#ifdef __cplusplus
}
#endif

#endif