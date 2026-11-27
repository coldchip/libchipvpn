#include <endian.h>
#include <string.h>
#include "packet.h"

#define CHIPVPN_PACKET_ALIGN 16U

size_t chipvpn_packet_pad(uint8_t *data, size_t unpadded, int mtu) {
	if(unpadded == 0) {
		return 0;
	}

	size_t padded = (unpadded + (CHIPVPN_PACKET_ALIGN - 1U)) & ~(size_t)(CHIPVPN_PACKET_ALIGN - 1U);
	if(mtu > 0 && padded > (size_t)mtu) {
		padded = MAX(unpadded, (size_t)mtu);
	}

	memset(data + unpadded, 0, padded - unpadded);
	return padded;
}

size_t chipvpn_packet_unpad(const uint8_t *data, size_t padded) {
	if(padded == 0) {
		return 0;
	}

	switch(data[0] >> 4) {
		case 4: {
			if(padded < sizeof(ipv4_hdr_t)) {
				return 0;
			}
			const ipv4_hdr_t *ipv4_hdr = (const ipv4_hdr_t *)data;
			size_t unpadded = be16toh(ipv4_hdr->ip_len);
			return (unpadded >= sizeof(ipv4_hdr_t) && unpadded <= padded) ? unpadded : 0;
		}
		case 6: {
			if(padded < sizeof(ipv6_hdr_t)) {
				return 0;
			}
			const ipv6_hdr_t *ipv6_hdr = (const ipv6_hdr_t *)data;
			size_t unpadded = sizeof(ipv6_hdr_t) + be16toh(ipv6_hdr->payload_len);
			return (unpadded <= padded) ? unpadded : 0;
		}
		default:
			return 0;
	}
}