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
	CHIPVPN_ADDRESS_NONE,
	CHIPVPN_ADDRESS_IPV4,
	CHIPVPN_ADDRESS_IPV6
} chipvpn_address_type_e;

typedef struct {
	chipvpn_address_type_e type;
	union {
		uint8_t ipv6[16];
		uint32_t ipv4;
	};
	uint16_t port;
	uint8_t prefix;
} chipvpn_address_t;

bool           chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip);
bool           chipvpn_address_cidr_match(const chipvpn_address_t *net, const chipvpn_address_t *addr);
bool           chipvpn_address_equal(const chipvpn_address_t *left, const chipvpn_address_t *right);
const char    *chipvpn_address_to_char(const chipvpn_address_t *addr);     

#ifdef __cplusplus
}
#endif

#endif