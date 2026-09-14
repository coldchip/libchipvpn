#ifndef ADDRESS_H
#define ADDRESS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/un.h>

#define UNIX_PATH_MAX sizeof(((struct sockaddr_un *)0)->sun_path)

/* "255.255.255.255" + NUL, rounded up */
#define CHIPVPN_ADDR_STR_LEN 24

typedef struct {
	uint32_t ip;
	uint16_t port;
	uint8_t prefix;
} chipvpn_address_t;

bool           chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip);
bool           chipvpn_address_cidr_match(chipvpn_address_t *addr, chipvpn_address_t *net);
void           chipvpn_address_to_str(const chipvpn_address_t *addr, char *buf, size_t buflen);
char          *chipvpn_address_to_char(chipvpn_address_t *addr);

#ifdef __cplusplus
}
#endif

#endif
