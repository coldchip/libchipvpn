#ifndef PEER_H
#define PEER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include "chipvpn.h"
#include "crypto.h"
#include "address.h"
#include "list.h"

typedef enum {
	PEER_ACTION_NONE,
	PEER_ACTION_CONNECT,
	PEER_ACTION_DISCONNECT
} chipvpn_peer_action_e;

typedef enum {
	PEER_DISCONNECTED,
	PEER_CONNECTED
} chipvpn_peer_state_e;

typedef struct {
	chipvpn_list_node_t node;
	chipvpn_peer_state_e state;
	chipvpn_crypto_t *crypto;
	uint32_t sender_id;
	uint32_t receiver_id;
	chipvpn_address_t address;
	chipvpn_address_t allow;
	uint64_t tx;
	uint64_t rx;
	uint32_t last_check;
	uint32_t last_ping;
	uint32_t timeout;
	chipvpn_peer_action_e action;
} chipvpn_peer_t;

chipvpn_peer_t      *chipvpn_peer_create();
bool                 chipvpn_peer_set_allow(chipvpn_peer_t *peer, const char *address, uint8_t prefix);
bool                 chipvpn_peer_set_endpoint(chipvpn_peer_t *peer, const char *address, uint16_t port);
bool                 chipvpn_peer_set_key(chipvpn_peer_t *peer, const char *key);
bool                 chipvpn_peer_exists(chipvpn_list_t *peers, chipvpn_peer_t *needle);
chipvpn_peer_t      *chipvpn_peer_get_by_keyhash(chipvpn_list_t *peers, char *key);
chipvpn_peer_t      *chipvpn_peer_get_by_allowip(chipvpn_list_t *peers, chipvpn_address_t *ip);
chipvpn_peer_t      *chipvpn_peer_get_by_index(chipvpn_list_t *peers, uint32_t index);
void                 chipvpn_peer_insert(chipvpn_device_t *device, chipvpn_peer_t *peer);
void                 chipvpn_peer_connect(chipvpn_peer_t *peer, uint32_t timeout);
void                 chipvpn_peer_disconnect(chipvpn_peer_t *peer, uint32_t timeout);
void                 chipvpn_peer_free(chipvpn_peer_t *peer);

#ifdef __cplusplus
}
#endif

#endif