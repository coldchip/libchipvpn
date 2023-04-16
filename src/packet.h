#ifndef PACKET_H
#define PACKET_H

typedef struct __attribute__((__packed__)) {
	uint8_t	version:4, ihl:4;
	uint8_t  ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
	uint8_t  ip_ttl;
	uint8_t  ip_p;
	uint16_t ip_sum;
	uint32_t src_addr;
	uint32_t dst_addr;
} ip_packet_t;

typedef struct __attribute__((__packed__)) {
	int type;
} chipvpn_packet_header_t;

typedef struct __attribute__((__packed__)) {
	chipvpn_packet_header_t header;
	int id;
	bool ack;
} chipvpn_packet_auth_t;

typedef struct __attribute__((__packed__)) {
	chipvpn_packet_header_t header;
	char iv[16];
} chipvpn_packet_data_t;

typedef struct __attribute__((__packed__)) {
	chipvpn_packet_header_t header;
	int id;
} chipvpn_packet_ping_t;

typedef union {
	chipvpn_packet_auth_t auth;
	chipvpn_packet_data_t data;
	chipvpn_packet_ping_t ping;
} chipvpn_packet_t;

#endif