#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include "chipvpn.h"
#include "packet.h"
#include "crypto.h"
#include "peer.h"

void chipvpn_peer_reset(chipvpn_peer_t *peer) {
	peer->state = PEER_DISCONNECTED;
	peer->tx = 0;
	peer->rx = 0;
	peer->last_check = 0;
	peer->timeout = 0;
	peer->connect = false;
}

void chipvpn_peer_connect(chipvpn_socket_t *socket, chipvpn_peer_t *peer) {
	chipvpn_packet_auth_t auth = {};
	auth.header.type = htonl(0);
	randombytes_buf(auth.nonce, sizeof(auth.nonce));
	crypto_hash_sha256((unsigned char*)auth.keyhash, (unsigned char*)peer->crypto.key, sizeof(peer->crypto.key));

	chipvpn_socket_write(socket, &auth, sizeof(auth), &peer->address);
}

bool chipvpn_peer_set_allow(chipvpn_peer_t *peer, const char *address, uint8_t prefix) {
	if(!chipvpn_address_set_ip(&peer->allow, address)) {
		return false;
	}
	peer->allow.prefix = prefix;
	return true;
}

bool chipvpn_peer_set_address(chipvpn_peer_t *peer, const char *address, uint16_t port) {
	if(!chipvpn_address_set_ip(&peer->address, address)) {
		return false;
	}
	peer->address.port = port;
	return true;
}

bool chipvpn_peer_set_key(chipvpn_peer_t *peer, const char *key) {
	char keyhash[crypto_hash_sha256_BYTES];
	crypto_hash_sha256((unsigned char*)keyhash, (unsigned char*)key, strlen(key));
	chipvpn_crypto_set_key(&peer->crypto, keyhash);
	return true;
}

bool chipvpn_peer_exists(chipvpn_peer_t *peers, int peer_count, chipvpn_peer_t *needle) {
	for(chipvpn_peer_t *peer = peers; peer < &peers[peer_count]; ++peer) {
		if(peer == needle) {
			return true;
		}
	}
	return false;
}

chipvpn_peer_t *chipvpn_peer_get_by_key(chipvpn_peer_t *peers, int peer_count, char *key) {
	for(chipvpn_peer_t *peer = peers; peer < &peers[peer_count]; ++peer) {
		if(memcmp(key, peer->crypto.key, sizeof(peer->crypto.key)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_keyhash(chipvpn_peer_t *peers, int peer_count, char *key) {
	for(chipvpn_peer_t *peer = peers; peer < &peers[peer_count]; ++peer) {
		char current[crypto_hash_sha256_BYTES];
		crypto_hash_sha256((unsigned char*)current, (unsigned char*)peer->crypto.key, sizeof(current));

		if(memcmp(key, current, sizeof(current)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_allowip(chipvpn_peer_t *peers, int peer_count, chipvpn_address_t *ip) {
	for(chipvpn_peer_t *peer = peers; peer < &peers[peer_count]; ++peer) {
		if(chipvpn_address_cidr_match(ip, &peer->allow)) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_session(chipvpn_peer_t *peers, int peer_count, uint32_t session) {
	for(chipvpn_peer_t *peer = peers; peer < &peers[peer_count]; ++peer) {
		if(session == peer->session) {
			return peer;
		}
	}
	return NULL;
}