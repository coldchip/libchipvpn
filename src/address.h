#ifndef ADDRESS_H
#define ADDRESS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/un.h>

typedef struct {
	uint32_t ip;
	uint16_t port;
	uint8_t prefix;
	struct sockaddr_un un;
} chipvpn_address_t;

bool chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip);
bool chipvpn_address_cidr_match(chipvpn_address_t *addr, chipvpn_address_t *net);

#ifdef __cplusplus
}
#endif

#endif