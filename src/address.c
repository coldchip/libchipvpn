#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "address.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

bool chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip) {
	if(inet_pton(AF_INET, ip, &addr->ipv4) == 1) {
		addr->type = CHIPVPN_ADDRESS_IPV4;
		return true;
	}
	
	if(inet_pton(AF_INET6, ip, addr->ipv6) == 1) {
		addr->type = CHIPVPN_ADDRESS_IPV6;
		return true;
	}
	
	return false;
}

bool chipvpn_address_cidr_match(chipvpn_address_t *net, chipvpn_address_t *addr) {
	if(net->type != addr->type) {
		return false;
	}

	if(net->prefix == 0) {
		return true;
	}

	if(net->type == CHIPVPN_ADDRESS_IPV4) {
		return !((addr->ipv4 ^ net->ipv4) & htonl(0xFFFFFFFFu << (32 - net->prefix)));
	}

	if(net->type == CHIPVPN_ADDRESS_IPV6) {
		uint8_t bytes = net->prefix / 8;
		uint8_t bits  = net->prefix % 8;

		if(bytes > 0 && memcmp(net->ipv6, addr->ipv6, bytes) != 0) {
			return false;
		}

		if(bits > 0) {
			uint8_t mask = (uint8_t)(0xFF << (8 - bits));
			if((net->ipv6[bytes] ^ addr->ipv6[bytes]) & mask) {
				return false;
			}
		}

		return true;
	}

	return false;
}

char *chipvpn_address_to_char(chipvpn_address_t *addr) {
	static char result[INET6_ADDRSTRLEN];

	if (addr->type == CHIPVPN_ADDRESS_IPV4) {
		if (inet_ntop(AF_INET, &addr->ipv4, result, sizeof(result)) != NULL) {
			return result;
		}
	} else if (addr->type == CHIPVPN_ADDRESS_IPV6) {
		if (inet_ntop(AF_INET6, addr->ipv6, result, sizeof(result)) != NULL) {
			return result;
		}
	}

	result[0] = '\0';
	return result;
}