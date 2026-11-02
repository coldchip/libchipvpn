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
        struct {
            uint8_t _ipv4_prefix[12]; // dualstack support: bytes 0-11: used for ::ffff:
            uint32_t ipv4;            // dualstack support: bytes 12-15: the actual v4 address
        };
    };
	uint16_t port;
	uint8_t prefix;
} chipvpn_address_t;

bool           chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip);
void           chipvpn_address_v4_mapped_v6(chipvpn_address_t *addr);
bool           chipvpn_address_cidr_match(chipvpn_address_t *net, chipvpn_address_t *addr);
char          *chipvpn_address_to_char(chipvpn_address_t *addr);     

#ifdef __cplusplus
}
#endif

#endif