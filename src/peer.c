#include <stdlib.h>
#include "peer.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}
	peer->state = PEER_DISCONNECTED;
	peer->last_ping = 0;
	return peer;
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	free(peer);
}