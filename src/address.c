#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "address.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

bool chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip) {
	addr->ip = inet_addr(ip);

	return true;
}

bool chipvpn_address_cidr_match(chipvpn_address_t *addr, chipvpn_address_t *net) {
	if (net->prefix == 0) {
		// C99 6.5.7 (3): u32 << 32 is undefined behaviour
		return true;
	}
	return !((addr->ip ^ net->ip) & htonl(0xFFFFFFFFu << (32 - net->prefix)));
}

char *chipvpn_address_to_char(chipvpn_address_t *addr) {
	static char result[24];

	sprintf(
		result, 
		"%u.%u.%u.%u", 
		(addr->ip >> 0) & 255, 
		(addr->ip >> 8) & 255, 
		(addr->ip >> 16) & 255, 
		(addr->ip >> 24) & 255
	);

	return result;
}