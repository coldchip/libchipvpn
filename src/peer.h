#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include "crypto.h"
#include "address.h"
#include "list.h"

typedef enum {
	PEER_DISCONNECTED,
	PEER_CONNECTED
} chipvpn_peer_state_e;

typedef struct {
	ListNode node;
	chipvpn_peer_state_e state;
	chipvpn_crypto_t *crypto;
	uint32_t sender_id;
	uint32_t receiver_id;
	bool connect;
	uint32_t last_ping;
	chipvpn_address_t address;
	chipvpn_address_t allow;
	uint64_t tx;
	uint64_t rx;
} chipvpn_peer_t;

chipvpn_peer_t      *chipvpn_peer_create();
chipvpn_peer_t      *chipvpn_peer_get_by_keyhash(List *peers, char *key);
chipvpn_peer_t      *chipvpn_peer_get_by_allowip(List *peers, chipvpn_address_t *ip);
chipvpn_peer_t      *chipvpn_peer_get_by_index(List *peers, uint32_t index);
void                 chipvpn_peer_free(chipvpn_peer_t *peer);

#endif