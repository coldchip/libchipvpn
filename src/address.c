#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "address.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

bool chipvpn_address_set_ip(chipvpn_address_t *address, const char *ip) {
	if(inet_pton(AF_INET, ip, &address->ipv4) == 1) {
		address->type = CHIPVPN_ADDRESS_IPV4;
		return true;
	}
	
	if(inet_pton(AF_INET6, ip, address->ipv6) == 1) {
		address->type = CHIPVPN_ADDRESS_IPV6;
		return true;
	}
	
	return false;
}

bool chipvpn_address_network_match(chipvpn_address_t *network, chipvpn_address_t *address) {
	if(network->type != address->type) {
		return false;
	}

	if(network->prefix == 0) {
		return true;
	}

	if(network->type == CHIPVPN_ADDRESS_IPV4) {
		return !((address->ipv4 ^ network->ipv4) & htonl(0xFFFFFFFFu << (32 - network->prefix)));
	}

	if(network->type == CHIPVPN_ADDRESS_IPV6) {
		uint8_t bytes = network->prefix / 8;
		uint8_t bits  = network->prefix % 8;

		if(bytes > 0 && memcmp(network->ipv6, address->ipv6, bytes) != 0) {
			return false;
		}

		if(bits > 0) {
			uint8_t mask = (uint8_t)(0xFF << (8 - bits));
			if((network->ipv6[bytes] ^ address->ipv6[bytes]) & mask) {
				return false;
			}
		}

		return true;
	}

	return false;
}

bool chipvpn_address_endpoint_match(chipvpn_address_t *left, chipvpn_address_t *right) {
	if(left->type != right->type || left->port != right->port) {
		return false;
	}

	if(left->type == CHIPVPN_ADDRESS_IPV4) {
		return left->ipv4 == right->ipv4;
	}

	if(left->type == CHIPVPN_ADDRESS_IPV6) {
		return memcmp(left->ipv6, right->ipv6, sizeof(left->ipv6)) == 0;
	}

	return false;
}

const char *chipvpn_address_to_char(chipvpn_address_t *address) {
	static char result[INET6_ADDRSTRLEN];

	if(address->type == CHIPVPN_ADDRESS_IPV4) {
		if(inet_ntop(AF_INET, &address->ipv4, result, sizeof(result)) != NULL) {
			return result;
		}
	}

	if(address->type == CHIPVPN_ADDRESS_IPV6) {
		if(inet_ntop(AF_INET6, address->ipv6, result, sizeof(result)) != NULL) {
			return result;
		}
	}

	result[0] = '\0';
	return result;
}