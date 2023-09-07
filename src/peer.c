#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include "chipvpn.h"
#include "packet.h"
#include "crypto.h"
#include "peer.h"

void chipvpn_peer_reset(chipvpn_peer_t *peer) {
	peer->state = PEER_DISCONNECTED;
	peer->timestamp = 0;
	peer->tx = 0;
	peer->rx = 0;
	peer->last_check = 0;
	peer->timeout = 0;
	peer->connect = false;
}

void chipvpn_peer_connect(chipvpn_socket_t *socket, chipvpn_peer_t *peer, bool ack) {
	peer->inbound_session = rand();

	char key[crypto_stream_xchacha20_KEYBYTES];
	char nonce[crypto_stream_xchacha20_NONCEBYTES];
	randombytes_buf((unsigned char*)key, sizeof(key));
	randombytes_buf((unsigned char*)nonce, sizeof(nonce));

	chipvpn_crypto_set_key(&peer->inbound_crypto, key);
	chipvpn_crypto_set_nonce(&peer->inbound_crypto, nonce);

	chipvpn_packet_auth_t auth = {};
	auth.header.type = htonl(0);
	auth.session = htonl(peer->inbound_session);
	auth.timestamp = htonll(chipvpn_get_time());
	auth.ack = ack;
	crypto_hash_sha256((unsigned char*)auth.keyhash, (unsigned char*)peer->key, sizeof(peer->key));
	memcpy(auth.crypto.key, key, sizeof(key));
	memcpy(auth.crypto.nonce, nonce, sizeof(nonce));
	memset(auth.totp, 0, sizeof(auth.totp));

	char nonce2[crypto_stream_xchacha20_NONCEBYTES] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};

	crypto_stream_xchacha20_xor_ic(
		(unsigned char*)&auth.crypto, 
		(unsigned char*)&auth.crypto, 
		sizeof(auth.crypto), 
		(unsigned char*)nonce2, 
		1024, 
		(unsigned char*)peer->key
	);

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
	crypto_hash_sha256((unsigned char*)peer->key, (unsigned char*)key, strlen(key));
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
		if(memcmp(key, peer->key, sizeof(peer->key)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_keyhash(chipvpn_peer_t *peers, int peer_count, char *key) {
	for(chipvpn_peer_t *peer = peers; peer < &peers[peer_count]; ++peer) {
		char current[crypto_hash_sha256_BYTES];
		crypto_hash_sha256((unsigned char*)current, (unsigned char*)peer->key, sizeof(current));

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
		if(session == peer->inbound_session) {
			return peer;
		}
	}
	return NULL;
}