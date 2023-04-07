#ifndef ADDRESS_H
#define ADDRESS_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
	uint32_t ip;
	uint16_t port;
	uint8_t prefix;
} chipvpn_address_t;

bool chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip);
bool chipvpn_address_cidr_match(chipvpn_address_t *addr, chipvpn_address_t *net);

#endif