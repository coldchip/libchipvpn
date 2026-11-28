#include <endian.h>
#include <string.h>
#include "address.h"
#include "packet.h"

#define ALIGN16(n) (((n) + 15U) & ~(size_t)15U)

size_t chipvpn_packet_pad_ip(uint8_t *data, size_t unpadded, int mtu) {
	if(unpadded < sizeof(ipv4_hdr_t)) {
		return 0;
	}

	size_t padded = ALIGN16(unpadded);
	if(mtu > 0 && padded > (size_t)mtu) {
		padded = MAX(unpadded, (size_t)mtu);
	}

	memset(data + unpadded, 0, padded - unpadded);
	return padded;
}

size_t chipvpn_packet_unpad_ip(const uint8_t *data, size_t padded) {
	if(padded < sizeof(ipv4_hdr_t)) {
		return 0;
	}

	size_t  unpadded = 0;
	uint8_t version  = data[0] >> 4;

	if(version == 4) {
		unpadded = be16toh(((const ipv4_hdr_t *)data)->ip_len);
	} else if(version == 6 && padded >= sizeof(ipv6_hdr_t)) {
		unpadded = sizeof(ipv6_hdr_t) + be16toh(((const ipv6_hdr_t *)data)->payload_len);
	}

	return (unpadded >= sizeof(ipv4_hdr_t) && unpadded <= padded) ? unpadded : 0;
}

bool chipvpn_packet_parse_ip(const uint8_t *data, size_t size, chipvpn_address_t *src, chipvpn_address_t *dst) {
	if(!data || size == 0) {
		return false;
	}

	switch(data[0] >> 4) {
		case 4: {
			if(size < sizeof(ipv4_hdr_t)) {
				return false;
			}

			const ipv4_hdr_t *hdr = (const ipv4_hdr_t *)data;

			if(src) {
				src->type = CHIPVPN_ADDRESS_IPV4; 
				src->ipv4 = hdr->src_addr;
			}

			if(dst) {
				dst->type = CHIPVPN_ADDRESS_IPV4; 
				dst->ipv4 = hdr->dst_addr;
			}
			
			return true;
		}
		case 6: {
			if(size < sizeof(ipv6_hdr_t)) {
				return false;
			}

			const ipv6_hdr_t *hdr = (const ipv6_hdr_t *)data;

			if(src) {
				src->type = CHIPVPN_ADDRESS_IPV6;
				memcpy(src->ipv6, hdr->src_addr, sizeof(hdr->src_addr));
			}

			if(dst) {
				dst->type = CHIPVPN_ADDRESS_IPV6;
				memcpy(dst->ipv6, hdr->dst_addr, sizeof(hdr->dst_addr));
			}

			return true;
		}
		default: {
			return false;
		}
	}
}