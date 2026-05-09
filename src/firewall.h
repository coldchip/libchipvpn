#ifndef FIREWALL_H
#define FIREWALL_H

#include "packet.h"

typedef struct {
	int mss;
} chipvpn_firewall_t;

int chipvpn_firewall_process_ip(chipvpn_firewall_t *firewall, ip_hdr_t *ip_hdr);

#endif