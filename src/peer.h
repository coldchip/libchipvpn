#ifndef PEER_H
#define PEER_H

#include "address.h"
#include "list.h"

typedef struct {
	ListNode node;
	int id;
	bool connect;
	chipvpn_address_t endpoint;
	chipvpn_address_t address;
	chipvpn_address_t allow;
} chipvpn_peer_t;

chipvpn_peer_t    *chipvpn_peer_create();
void               chipvpn_peer_free(chipvpn_peer_t *peer);

#endif