#include <stdlib.h>
#include "crypto.h"
#include "peer.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}
	peer->sender_id = 0;
	peer->receiver_id = 0;
	peer->state = PEER_DISCONNECTED;
	peer->crypto = chipvpn_crypto_create();
	peer->last_ping = 0;
	peer->connect = false;
	return peer;
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	chipvpn_crypto_free(peer->crypto);
	free(peer);
}