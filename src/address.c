#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "address.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

/*
 * Parse a dotted-decimal IPv4 string into addr->ip.
 * Returns false if inet_addr signals an error (INADDR_NONE).
 */
bool chipvpn_address_set_ip(chipvpn_address_t *addr, const char *ip) {
	in_addr_t result = inet_addr(ip);
	if(result == INADDR_NONE) {
		return false;
	}
	addr->ip = result;
	return true;
}

/*
 * Returns true when addr falls inside the CIDR prefix described by net.
 * Handles the /0 special case to avoid undefined behaviour from a 32-bit shift.
 */
bool chipvpn_address_cidr_match(chipvpn_address_t *addr, chipvpn_address_t *net) {
	if(net->prefix == 0) {
		/* /0 matches everything; u32 << 32 is undefined behaviour in C */
		return true;
	}
	return !((addr->ip ^ net->ip) & htonl(0xFFFFFFFFu << (32 - net->prefix)));
}

/*
 * Format addr->ip as a dotted-decimal string and return a pointer to
 * a caller-supplied buffer of at least CHIPVPN_ADDR_STR_LEN bytes.
 */
void chipvpn_address_to_str(const chipvpn_address_t *addr, char *buf, size_t buflen) {
	snprintf(
		buf, buflen,
		"%u.%u.%u.%u",
		(addr->ip >>  0) & 0xFF,
		(addr->ip >>  8) & 0xFF,
		(addr->ip >> 16) & 0xFF,
		(addr->ip >> 24) & 0xFF
	);
}

/*
 * Convenience wrapper that writes into a local static buffer.
 * NOT re-entrant: do not call twice in the same expression.
 */
char *chipvpn_address_to_char(chipvpn_address_t *addr) {
	static char result[CHIPVPN_ADDR_STR_LEN];
	chipvpn_address_to_str(addr, result, sizeof(result));
	return result;
}
