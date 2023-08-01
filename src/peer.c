#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include "chipvpn.h"
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

bool chipvpn_peer_set_allow(chipvpn_peer_t *peer, const char *value) {
	char ip[24];
	int prefix;
	if(sscanf(value, "%16[^/]/%i", ip, &prefix) == 2) {
		if(!chipvpn_address_set_ip(&peer->allow, ip)) {
			return false;
		}
		peer->allow.prefix = prefix;
	}
	return true;
}

bool chipvpn_peer_set_endpoint(chipvpn_peer_t *peer, const char *value) {
	char ip[24];
	int port;
	if(sscanf(value, "%16[^:]:%i", ip, &port) == 2) {
		if(!chipvpn_address_set_ip(&peer->address, ip)) {
			return false;
		}
		peer->address.port = port;
	}
	return true;
}

bool chipvpn_peer_set_key(chipvpn_peer_t *peer, const char *key) {
	char keyhash[crypto_stream_xchacha20_KEYBYTES];
	crypto_hash_sha256((unsigned char*)keyhash, (unsigned char*)key, strlen(key));
	chipvpn_crypto_set_key(peer->crypto, keyhash);

	return true;
}

bool chipvpn_peer_exists(chipvpn_list_t *peers, chipvpn_peer_t *needle) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(peer == needle) {
			return true;
		}
	}
	return false;
}

chipvpn_peer_t *chipvpn_peer_get_by_keyhash(chipvpn_list_t *peers, char *key) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		char current[crypto_hash_sha256_BYTES];
		crypto_hash_sha256((unsigned char*)current, (unsigned char*)peer->crypto->key, sizeof(current));

		if(memcmp(key, current, sizeof(current)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_allowip(chipvpn_list_t *peers, chipvpn_address_t *ip) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_address_cidr_match(ip, &peer->allow)) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_index(chipvpn_list_t *peers, uint32_t index) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(index == peer->sender_id) {
			return peer;
		}
	}
	return NULL;
}

void chipvpn_peer_connect(chipvpn_peer_t *peer) {
	peer->connect = true;
	peer->state = PEER_DISCONNECTED;
}

void chipvpn_peer_disconnect(chipvpn_peer_t *peer) {
	peer->connect = false;
	peer->state = PEER_DISCONNECTED;
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	chipvpn_crypto_free(peer->crypto);
	free(peer);
}