#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "packet.h"
#include "crypto.h"
#include "util.h"
#include "xchacha20.h"
#include "sha256.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	peer->state = PEER_DISCONNECTED;
	peer->timestamp = 0;
	peer->tx = 0;
	peer->rx = 0;
	peer->tx_packet = 0;
	peer->rx_packet = 0;
	peer->last_check = 0;
	peer->timeout = 0;
	peer->connect = false;
	peer->onconnect = NULL;
	peer->onping = NULL;
	peer->ondisconnect = NULL;
	peer->counter = 0l;

	return peer;
}

void chipvpn_peer_connect(chipvpn_socket_t *socket, chipvpn_peer_t *peer, bool ack) {
	chipvpn_secure_random((char*)&peer->inbound_session, sizeof(peer->inbound_session));

	chipvpn_secure_random((char*)&peer->inbound_crypto.key, sizeof(peer->inbound_crypto.key));
	chipvpn_secure_random((char*)&peer->inbound_crypto.nonce, sizeof(peer->inbound_crypto.nonce));

	chipvpn_packet_auth_t packet = {
		.version = 173,
		.header.type = CHIPVPN_PACKET_AUTH,
		.session = htonl(peer->inbound_session),
		.timestamp = htonll(chipvpn_get_time()),
		.ack = ack
	};

	SHA256_CTX state0;
	sha256_init(&state0);
	sha256_update(&state0, (unsigned char*)peer->key, sizeof(peer->key));
	sha256_final(&state0, (unsigned char*)packet.keyhash);

	chipvpn_secure_random((char*)&packet.nonce, sizeof(packet.nonce));

	xchacha_xcrypt(
		(unsigned char*)&packet.crypto, 
		(unsigned char*)&peer->inbound_crypto, 
		sizeof(packet.crypto), 
		(unsigned char*)peer->key,
		(unsigned char*)packet.nonce, 
		1024
	);

	memset(packet.sign, 0, sizeof(packet.sign));

	unsigned char sign[32];

	SHA256_CTX state;
	sha256_init(&state);
	sha256_update(&state, (unsigned char*)&packet, sizeof(packet));
	sha256_update(&state, (unsigned char*)peer->key, sizeof(peer->key));
	sha256_final(&state, sign);

	memcpy(packet.sign, sign, sizeof(packet.sign));

	chipvpn_socket_write(socket, &packet, sizeof(packet), &peer->address);
}

void chipvpn_peer_ping(chipvpn_socket_t *socket, chipvpn_peer_t *peer) {
	chipvpn_packet_ping_t packet = {};
	packet.header.type = CHIPVPN_PACKET_PING;
	packet.session = htonl(peer->outbound_session);
	packet.counter = htonll(peer->counter);

	peer->counter += 1;

	memset(packet.sign, 0, sizeof(packet.sign));

	unsigned char sign[32];
	SHA256_CTX state;
	sha256_init(&state);
	sha256_update(&state, (unsigned char*)&packet, sizeof(packet));
	sha256_update(&state, (unsigned char*)peer->key, sizeof(peer->key));
	sha256_final(&state, sign);

	memcpy(packet.sign, sign, sizeof(packet.sign));

	if(peer->onping) {
		chipvpn_peer_run_command(peer, peer->onping);
	}

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
	SHA256_CTX state;
	sha256_init(&state);
	sha256_update(&state, (unsigned char*)key, strlen(key));
	sha256_final(&state, (unsigned char*)peer->key);

	return true;
}

bool chipvpn_peer_set_onconnect(chipvpn_peer_t *peer, const char *onconnect) {
	peer->onconnect = strdup(onconnect);
	return true;
}

bool chipvpn_peer_set_onping(chipvpn_peer_t *peer, const char *onping) {
	peer->onping = strdup(onping);
	return true;
}

bool chipvpn_peer_set_ondisconnect(chipvpn_peer_t *peer, const char *ondisconnect) {
	peer->ondisconnect = strdup(ondisconnect);
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

		char current[32];
		
		SHA256_CTX state;
		sha256_init(&state);
		sha256_update(&state, (unsigned char*)peer->key, sizeof(current));
		sha256_final(&state, (unsigned char*)current);

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
		switch(state) {
			case PEER_CONNECTED: {
				if(peer->onconnect) {
					chipvpn_peer_run_command(peer, peer->onconnect);
				}
			}
			break;
			case PEER_DISCONNECTED: {
				if(peer->ondisconnect) {
					chipvpn_peer_run_command(peer, peer->ondisconnect);
				}
			}
			break;
		}
		peer->state = state;
	}
}

void chipvpn_peer_run_command(chipvpn_peer_t *peer, const char *command) {
	char gateway[16];
	char dev[16];
	if(!get_gateway(gateway, dev)) {

	}

	char tx[16];
	char rx[16];

	if(peer) {
		sprintf(tx, "%lu", peer->tx);
		sprintf(rx, "%lu", peer->rx);
	}

	char *result1 = str_replace(command, "%gateway%", gateway);
	char *result2 = str_replace(result1, "%gatewaydev%", dev);
	char *result3 = str_replace(result2, "%tx%", tx);
	char *result4 = str_replace(result3, "%rx%", rx);
	if(system(result4) == 0) {
		printf("%s\n", result4);
	}
	free(result1);
	free(result2);
	free(result3);
	free(result4);
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	if(peer->onconnect) {
		free(peer->onconnect);
	}

	if(peer->onping) {
		free(peer->onping);
	}

	if(peer->ondisconnect) {
		free(peer->ondisconnect);
	}

	free(peer);
}