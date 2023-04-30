#include <stdlib.h>
#include <sodium.h>
#include <string.h>
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
	peer->tx = 0;
	peer->rx = 0;
	return peer;
}

chipvpn_peer_t *chipvpn_peer_get_by_keyhash(List *peers, char *key) {
	for(ListNode *p = list_begin(peers); p != list_end(peers); p = list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		char current[crypto_hash_sha256_BYTES];
		crypto_hash_sha256((unsigned char*)current, (unsigned char*)peer->crypto->key, sizeof(current));

		if(memcmp(key, current, sizeof(current)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_allowip(List *peers, chipvpn_address_t *ip) {
	for(ListNode *p = list_begin(peers); p != list_end(peers); p = list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_address_cidr_match(ip, &peer->allow)) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_index(List *peers, uint32_t index) {
	for(ListNode *p = list_begin(peers); p != list_end(peers); p = list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(index == peer->sender_id) {
			return peer;
		}
	}
	return NULL;
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	chipvpn_crypto_free(peer->crypto);
	free(peer);
}