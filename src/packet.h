#ifndef PACKET_H
#define PACKET_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
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
	CHIPVPN_PACKET_AUTH = 1,
	CHIPVPN_PACKET_AUTH_REPLY = 2,
	CHIPVPN_PACKET_DATA = 4,
} chipvpn_packet_type_e;

typedef struct __attribute__((__packed__)) {
	uint8_t type;
} chipvpn_packet_header_t;

typedef struct __attribute__((__packed__)) {
	chipvpn_packet_header_t header;
	uint8_t padding[3];
	uint32_t sender_index;
	uint8_t ephemeral_public[CURVE25519_KEY_SIZE];
	uint8_t static_public[CURVE25519_KEY_SIZE];
	uint8_t static_public_mac[16];
	uint8_t timestamp[12];
	uint8_t timestamp_mac[16];
	uint8_t mac1[16];
	uint8_t mac2[16];
} chipvpn_wg_packet_auth_t;

typedef struct __attribute__((__packed__)) {
    chipvpn_packet_header_t header; 
    uint8_t padding[3];             
    uint32_t sender_index;          
    uint32_t receiver_index;        
    uint8_t ephemeral_public[32];  
    uint8_t empty_mac[16];        
    uint8_t mac1[16];              
    uint8_t mac2[16];             
} chipvpn_wg_packet_auth_resp_t; 

typedef struct __attribute__((__packed__)) {
	chipvpn_packet_header_t header;
	uint8_t padding[3]; 
	uint32_t session;
	uint64_t counter;
} chipvpn_packet_data_t;

#ifdef __cplusplus
}
#endif

#endif