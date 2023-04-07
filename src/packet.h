#ifndef PACKET_H
#define PACKET_H

typedef struct __attribute__((__packed__)) {
	int type;
	int id;
	char iv[16];
} chipvpn_packet_t;

typedef struct __attribute__((__packed__)) {
	uint8_t	version:4, ihl:4;
    uint8_t  ip_tos;                 /* type of service */
    uint16_t ip_len;                 /* total length */
    uint16_t ip_id;                  /* identification */
    uint16_t ip_off;                 /* fragment offset field */
    uint8_t  ip_ttl;                 /* time to live */
    uint8_t  ip_p;                   /* protocol */
    uint16_t ip_sum;                 /* checksum */
   	uint32_t src_addr;   			 /* source IP address. */
    uint32_t dst_addr;				 /* dest IP address. */
} ip_packet_t;

#endif