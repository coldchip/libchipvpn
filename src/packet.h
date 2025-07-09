#ifndef PACKET_H
#define PACKET_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "curve25519.h"

typedef struct __attribute__((__packed__)) {
# if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;
    uint8_t version:4;
# elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;
    uint8_t ihl:4;
# else
#	error "Please fix <bits/endian.h>"
# endif
	uint8_t  ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
	uint8_t  ip_ttl;
	uint8_t  ip_p;
	uint16_t ip_sum;
	uint32_t src_addr;
	uint32_t dst_addr;
} ip_hdr_t;

typedef struct __attribute__((__packed__)) {
	uint16_t src;
	uint16_t dst;
	uint32_t seq;
	uint32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t res1:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#  else
#	error "Please fix <bits/endian.h>"
#  endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
} tcp_hdr_t;

typedef struct {
	uint16_t src;
	uint16_t dst;
	uint16_t len;
	uint16_t check;
} udp_hdr_t;

typedef struct {
	uint16_t src;
	uint16_t dst;
} udp_tcp_port_t;

typedef enum {
	CHIPVPN_PACKET_AUTH = 0,
	CHIPVPN_PACKET_DATA,
	CHIPVPN_PACKET_PING,
} chipvpn_packet_type_e;

typedef struct __attribute__((__packed__)) {
	uint8_t type;
} chipvpn_packet_header_t;

typedef struct __attribute__((__packed__)) {
	chipvpn_packet_header_t header;
	uint32_t version;
	char keyhash[32];
	char ecdh_public[CURVE25519_KEY_SIZE];
	uint64_t timestamp;
	bool ack;
	char sign[32];
} chipvpn_packet_auth_t;

typedef struct __attribute__((__packed__)) {
	chipvpn_packet_header_t header;
	uint32_t session;
	uint64_t counter;
	char mac[16];
} chipvpn_packet_data_t;

typedef struct __attribute__((__packed__)) {
	chipvpn_packet_header_t header;
	uint32_t session;
	uint64_t counter;
	char sign[32];
} chipvpn_packet_ping_t;

#ifdef __cplusplus
}
#endif

#endif