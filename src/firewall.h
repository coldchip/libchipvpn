#ifndef FIREWALL_H
#define FIREWALL_H

#include "packet.h"

typedef struct {
	uint16_t mss;
} chipvpn_firewall_t;

void    chipvpn_firewall_reset(chipvpn_firewall_t *firewall);
int     chipvpn_firewall_process_ip(chipvpn_firewall_t *firewall, ip_hdr_t *ip_hdr);

#endif