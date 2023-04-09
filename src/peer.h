#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include "address.h"
#include "list.h"

typedef enum {
	PEER_DISCONNECTED,
	PEER_CONNECTED
} chipvpn_peer_state_e;

typedef struct {
	ListNode node;
	chipvpn_peer_state_e state;
	int id;
	bool connect;
	uint32_t last_ping;
	chipvpn_address_t endpoint;
	chipvpn_address_t address;
	chipvpn_address_t allow;
} chipvpn_peer_t;

chipvpn_peer_t    *chipvpn_peer_create();
void               chipvpn_peer_free(chipvpn_peer_t *peer);

#endif