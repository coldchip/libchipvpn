#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <netdb.h>
#include "address.h"

bool chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip) {
	if(!inet_aton(ip, (struct in_addr *)&addr->ip)) {
		return false;
	}
	return true;
}

bool chipvpn_address_set_domain(chipvpn_address_t *addr, const char *domain) {
	struct hostent *he = gethostbyname(domain);
	if(he == NULL) {
		return false;
	}
	struct in_addr *ip = ((struct in_addr **)he->h_addr_list)[0];
	if(ip == NULL) {
		return false;
	}

	addr->ip = (uint32_t)ip->s_addr;

	return true;
}

bool chipvpn_address_cidr_match(chipvpn_address_t *addr, chipvpn_address_t *net) {
	if (net->prefix == 0) {
		// C99 6.5.7 (3): u32 << 32 is undefined behaviour
		return true;
	}
	return !((addr->ip ^ net->ip) & htonl(0xFFFFFFFFu << (32 - net->prefix)));
}