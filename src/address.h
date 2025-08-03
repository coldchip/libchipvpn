#ifndef ADDRESS_H
#define ADDRESS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/un.h>

#define UNIX_PATH_MAX sizeof(((struct sockaddr_un *)0)->sun_path)

typedef struct {
	uint32_t ip;
	uint16_t port;
	uint8_t prefix;
} chipvpn_address_t;

bool           chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip);
bool           chipvpn_address_cidr_match(chipvpn_address_t *addr, chipvpn_address_t *net);
char          *chipvpn_address_to_char(chipvpn_address_t *addr);     

#ifdef __cplusplus
}
#endif

#endif