#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include "chipvpn.h"
#include "packet.h"
#include "crypto.h"
#include "firewall.h"
#include "peer.h"
#include "util.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	peer->state = PEER_DISCONNECTED;
	peer->firewall = chipvpn_firewall_create();
	peer->timestamp = 0;
	peer->tx = 0;
	peer->rx = 0;
	peer->last_check = 0;
	peer->timeout = 0;
	peer->connect = false;

	chipvpn_firewall_rule_t *in = malloc(sizeof(chipvpn_firewall_rule_t));
	chipvpn_address_set_ip(&in->address, "0.0.0.0");
	in->address.prefix = 0;
	in->protocol = 255;
	chipvpn_list_insert(chipvpn_list_end(&peer->firewall->outbound), in);

	chipvpn_firewall_rule_t *out = malloc(sizeof(chipvpn_firewall_rule_t));
	chipvpn_address_set_ip(&out->address, "0.0.0.0");
	out->address.prefix = 0;
	out->protocol = 255;
	chipvpn_list_insert(chipvpn_list_end(&peer->firewall->inbound), out);

	return peer;
}

void chipvpn_peer_connect(chipvpn_socket_t *socket, chipvpn_peer_t *peer, bool ack) {
	peer->inbound_session = rand();
	randombytes_buf((unsigned char*)&peer->inbound_crypto.key, sizeof(peer->inbound_crypto.key));
	randombytes_buf((unsigned char*)&peer->inbound_crypto.nonce, sizeof(peer->inbound_crypto.nonce));

	chipvpn_packet_auth_t packet = {};
	packet.header.type = CHIPVPN_PACKET_AUTH;
	packet.session = htonl(peer->inbound_session);
	packet.timestamp = htonll(chipvpn_get_time());
	packet.ack = ack;
	crypto_hash_sha256((unsigned char*)packet.keyhash, (unsigned char*)peer->key, sizeof(peer->key));
	randombytes_buf((unsigned char*)packet.nonce, sizeof(packet.nonce));

	crypto_stream_xchacha20_xor_ic(
		(unsigned char*)&packet.crypto, 
		(unsigned char*)&peer->inbound_crypto, 
		sizeof(packet.crypto), 
		(unsigned char*)packet.nonce, 
		1024, 
		(unsigned char*)peer->key
	);

	memset(packet.sign, 0, sizeof(packet.sign));

	unsigned char sign[crypto_hash_sha256_BYTES];
	crypto_hash_sha256_state state;
	crypto_hash_sha256_init(&state);
	crypto_hash_sha256_update(&state, (unsigned char*)&packet, sizeof(packet));
	crypto_hash_sha256_update(&state, (unsigned char*)peer->key, sizeof(peer->key));
	crypto_hash_sha256_final(&state, sign);

	memcpy(packet.sign, sign, sizeof(packet.sign));

	chipvpn_socket_write(socket, &packet, sizeof(packet), &peer->address);
}

void chipvpn_peer_ping(chipvpn_socket_t *socket, chipvpn_peer_t *peer) {
	chipvpn_packet_ping_t packet = {};
	packet.header.type = CHIPVPN_PACKET_PING;
	packet.session = htonl(peer->outbound_session);

	chipvpn_socket_write(socket, &packet, sizeof(packet), &peer->address);
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

bool chipvpn_peer_set_postup(chipvpn_peer_t *peer, const char *postup) {
	peer->postup = strdup(postup);
	return true;
}

bool chipvpn_peer_set_postdown(chipvpn_peer_t *peer, const char *postdown) {
	peer->postdown = strdup(postdown);
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

chipvpn_peer_t *chipvpn_peer_get_by_key(chipvpn_list_t *peers, char *key) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(memcmp(key, peer->key, sizeof(peer->key)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_keyhash(chipvpn_list_t *peers, char *key) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		char current[crypto_hash_sha256_BYTES];
		crypto_hash_sha256((unsigned char*)current, (unsigned char*)peer->key, sizeof(current));

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

chipvpn_peer_t *chipvpn_peer_get_by_session(chipvpn_list_t *peers, uint32_t session) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		
		if(session == peer->inbound_session) {
			return peer;
		}
	}
	return NULL;
}

void chipvpn_peer_set_status(chipvpn_peer_t *peer, chipvpn_peer_state_e state) {
	if(peer->state != state) {
		char *command = NULL;

		switch(state) {
			case PEER_CONNECTED: {
				command = peer->postup;
			}
			break;
			case PEER_DISCONNECTED: {
				command = peer->postdown;
			}
			break;
		}

		if(command) {
			char gateway[16];
			if(!get_gateway(gateway)) {

			}

			char *result = str_replace(command, "%gateway%", gateway);
			if(system(result) == 0) {
				printf("executed command\n");
			}
			free(result);
		}

		peer->state = state;
	}
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	chipvpn_firewall_free(peer->firewall);

	if(peer->postup) {
		free(peer->postup);
	}

	if(peer->postdown) {
		free(peer->postdown);
	}

	free(peer);
}