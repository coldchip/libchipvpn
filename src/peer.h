#ifndef PEER_H
#define PEER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include "crypto.h"
#include "socket.h"
#include "address.h"
#include "bitmap.h"
#include "list.h"

typedef enum {
	PEER_DISCONNECTED,
	PEER_CONNECTED
} chipvpn_peer_state_e;

typedef struct {
	chipvpn_list_node_t node;
	chipvpn_peer_state_e state;
	chipvpn_crypto_t outbound_crypto;
	chipvpn_crypto_t inbound_crypto;
	uint32_t outbound_session;
	uint32_t inbound_session;
	chipvpn_address_t address;

	struct {
		chipvpn_address_t address;
		chipvpn_address_t allow;
		bool connect;
		char key[32];
		char *onconnect;
		char *onping;
		char *ondisconnect;
	} config;

	uint64_t timestamp;
	uint64_t tx;
	uint64_t rx;
	uint64_t last_check;
	uint64_t timeout;
	uint64_t counter;
	chipvpn_bitmap_t bitmap;
} chipvpn_peer_t;

chipvpn_peer_t      *chipvpn_peer_create();
int                  chipvpn_peer_connect(chipvpn_socket_t *socket, chipvpn_peer_t *peer, chipvpn_address_t *addr, bool ack);
int                  chipvpn_peer_ping(chipvpn_socket_t *socket, chipvpn_peer_t *peer);
bool                 chipvpn_peer_set_allow(chipvpn_peer_t *peer, const char *address, uint8_t prefix);
bool                 chipvpn_peer_set_address(chipvpn_peer_t *peer, const char *address, uint16_t port);
bool                 chipvpn_peer_set_key(chipvpn_peer_t *peer, const char *key);
bool                 chipvpn_peer_set_onconnect(chipvpn_peer_t *peer, const char *command);
bool                 chipvpn_peer_set_onping(chipvpn_peer_t *peer, const char *command);
bool                 chipvpn_peer_set_ondisconnect(chipvpn_peer_t *peer, const char *command);
chipvpn_peer_t      *chipvpn_peer_get_by_key(chipvpn_list_t *peers, char *key);
chipvpn_peer_t      *chipvpn_peer_get_by_keyhash(chipvpn_list_t *peers, char *key);
chipvpn_peer_t      *chipvpn_peer_get_by_allowip(chipvpn_list_t *peers, chipvpn_address_t *ip);
chipvpn_peer_t      *chipvpn_peer_get_by_session(chipvpn_list_t *peers, uint32_t session);
void                 chipvpn_peer_set_state(chipvpn_peer_t *peer, chipvpn_peer_state_e state);
void                 chipvpn_peer_run_command(chipvpn_peer_t *peer, const char *command);
void                 chipvpn_peer_free(chipvpn_peer_t *peer);

#ifdef __cplusplus
}
#endif

#endif