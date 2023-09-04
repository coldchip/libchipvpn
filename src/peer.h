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

typedef enum {
	PEER_DISCONNECTED,
	PEER_CONNECTED
} chipvpn_peer_state_e;

typedef struct {
	chipvpn_peer_state_e state;
	chipvpn_crypto_t crypto;
	chipvpn_crypto_t crypto2;
	uint32_t session;
	uint32_t session2;
	chipvpn_address_t address;
	chipvpn_address_t allow;
	uint64_t tx;
	uint64_t rx;
	uint64_t last_check;
	uint64_t timeout;
	bool connect;
} chipvpn_peer_t;

void                 chipvpn_peer_reset(chipvpn_peer_t *peer);
void                 chipvpn_peer_connect(chipvpn_socket_t *socket, chipvpn_peer_t *peer, bool ack);
bool                 chipvpn_peer_set_allow(chipvpn_peer_t *peer, const char *address, uint8_t prefix);
bool                 chipvpn_peer_set_address(chipvpn_peer_t *peer, const char *address, uint16_t port);
bool                 chipvpn_peer_set_key(chipvpn_peer_t *peer, const char *key);
bool                 chipvpn_peer_exists(chipvpn_peer_t *peers, int peer_count, chipvpn_peer_t *needle);
chipvpn_peer_t      *chipvpn_peer_get_by_key(chipvpn_peer_t *peers, int peer_count, char *key);
chipvpn_peer_t      *chipvpn_peer_get_by_keyhash(chipvpn_peer_t *peers, int peer_count, char *key);
chipvpn_peer_t      *chipvpn_peer_get_by_allowip(chipvpn_peer_t *peers, int peer_count, chipvpn_address_t *ip);
chipvpn_peer_t      *chipvpn_peer_get_by_session(chipvpn_peer_t *peers, int peer_count, uint32_t session);

#ifdef __cplusplus
}
#endif

#endif