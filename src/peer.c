#include "peer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "packet.h"
#include "util.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "log.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	/* use setter to set? */
	peer->state = PEER_DISCONNECTED;
	peer->session = 0;
	peer->tx = 0l;
	peer->rx = 0l;
	peer->last_check = 0l;
	peer->timeout = 0l;
	peer->config.connect = false;
	peer->config.onconnect = NULL;
	peer->config.onping = NULL;
	peer->config.ondisconnect = NULL;
	peer->timeout = 0l;
	peer->counter = 0l;
	peer->timestamp = 0l;

	chipvpn_bitmap_reset(&peer->bitmap);

	return peer;
}

int chipvpn_peer_send_connect(chipvpn_t *vpn, chipvpn_peer_t *peer, chipvpn_address_t *addr, bool ack) {
	chipvpn_secure_random((char*)&peer->session, sizeof(peer->session));

	chipvpn_packet_auth_t packet = {
		.header.type = CHIPVPN_PACKET_AUTH,
		.version = htonl(CHIPVPN_PROTOCOL_VERSION),
		.session = htonl(peer->session),
		.timestamp = htonll(chipvpn_get_time()),
		.ack = ack
	};

	/* generate keyhash */
	hmac_sha256(
		peer->config.key, 
		sizeof(peer->config.key),
		"#CHIPVPN_KEYHASH",
		16,
		packet.keyhash, 
		sizeof(packet.keyhash)
	);

	/* generate nonce and sha256 the key */
	chipvpn_secure_random(packet.nonce, sizeof(packet.nonce));
	memcpy(peer->crypto.key, packet.nonce, sizeof(packet.nonce));

	/* sign entire packet */
	memset(packet.sign, 0, sizeof(packet.sign));
	hmac_sha256(
		peer->config.key, 
		sizeof(peer->config.key),
		&packet,
		sizeof(packet),
		packet.sign, 
		sizeof(packet.sign)
	);

	/* write to socket */
	return chipvpn_socket_write(vpn->socket, &packet, sizeof(packet), addr);
}

int chipvpn_peer_recv_connect(chipvpn_t *vpn, chipvpn_peer_t *peer, chipvpn_packet_auth_t *packet, chipvpn_address_t *addr) {
	char sign[32];
	char computed_sign[32];
	memcpy(sign, packet->sign, sizeof(sign));
	memset(packet->sign, 0, sizeof(packet->sign));

	hmac_sha256(
		peer->config.key, 
		sizeof(peer->config.key),
		packet,
		sizeof(chipvpn_packet_auth_t),
		computed_sign,
		sizeof(computed_sign)
	);

	if(memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
		chipvpn_log_append("invalid sign\n");
		return 0;
	}

	if(ntohl(packet->version) != CHIPVPN_PROTOCOL_VERSION) {
		chipvpn_log_append("invalid protocol version\n");
		return 0;
	}

	if(ntohll(packet->timestamp) <= peer->timestamp) {
		chipvpn_log_append("packet is replayed or duplicated\n");
		return 0;
	}

	if(
		chipvpn_get_time() - (60 * 1000 * 5) > ntohll(packet->timestamp) ||
		chipvpn_get_time() + (60 * 1000 * 5) < ntohll(packet->timestamp)
	) {
		chipvpn_log_append("invalid time range from peer\n");
		return 0;
	}

	// Auth successful
	if(packet->ack) {
		chipvpn_log_append("%p says: peer requested auth acknowledgement\n", peer);
		chipvpn_peer_send_connect(vpn, peer, addr, 0);
	}

	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	peer->session ^= ntohl(packet->session);
	peer->address = *addr;
	peer->timestamp = ntohll(packet->timestamp);
	peer->tx = 0l;
	peer->rx = 0l;
	peer->counter = 0l;
	peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;
	chipvpn_bitmap_reset(&peer->bitmap);
	chipvpn_peer_set_state(peer, PEER_CONNECTED);

	// Mix key
	char mix_keys[32];
	for(int i = 0; i < 0; i++) {
		mix_keys[i] = peer->crypto.key[i] ^ packet->nonce[i];
	}

	hmac_sha256(
		peer->config.key, 
		sizeof(peer->config.key),
		mix_keys,
		sizeof(mix_keys),
		peer->crypto.key,
		sizeof(peer->crypto.key)
	);

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session id: [%08x]\n", peer, peer->session);
	
	chipvpn_log_append("%p says: nonce: ", peer);
	for(int i = 0; i < sizeof(mix_keys); i++) {
		chipvpn_log_append("%02x", mix_keys[i] & 0xff);
	}
	chipvpn_log_append("\n");

	chipvpn_log_append("%p says: peer connected from [%s:%i]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	return 0;
}

int chipvpn_peer_send_ping(chipvpn_t *vpn, chipvpn_peer_t *peer) {
	chipvpn_packet_ping_t packet = {};
	packet.header.type = CHIPVPN_PACKET_PING;
	packet.session = htonl(peer->session);
	packet.counter = htonll(peer->counter);

	peer->counter += 1;

	/* sign entire packet */
	memset(packet.sign, 0, sizeof(packet.sign));
	hmac_sha256(
		peer->config.key, 
		sizeof(peer->config.key),
		&packet,
		sizeof(packet),
		packet.sign, 
		sizeof(packet.sign)
	);

	if(peer->config.onping) {
		chipvpn_peer_run_command(peer, peer->config.onping);
	}

	return chipvpn_socket_write(vpn->socket, &packet, sizeof(packet), &peer->address);
}

int chipvpn_peer_recv_ping(chipvpn_peer_t *peer, chipvpn_packet_ping_t *packet, chipvpn_address_t *addr) {
	if(peer->address.ip != addr->ip || peer->address.port != addr->port) {
		chipvpn_log_append("%p says: invalid src ip or src port\n", peer);
		return 0;
	}

	char sign[32];
	char computed_sign[32];
	memcpy(sign, packet->sign, sizeof(sign));
	memset(packet->sign, 0, sizeof(packet->sign));

	hmac_sha256(
		peer->config.key, 
		sizeof(peer->config.key),
		packet,
		sizeof(chipvpn_packet_ping_t),
		computed_sign,
		sizeof(computed_sign)
	);

	if(memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
		chipvpn_log_append("%p says: invalid ping sign\n", peer);
		return 0;
	}

	chipvpn_log_append("%p says: received ping from peer\n", peer);

	char tx[128];
	char rx[128];
	strcpy(tx, chipvpn_format_bytes(peer->tx));
	strcpy(rx, chipvpn_format_bytes(peer->rx));

	chipvpn_log_append("%p says: tx: [%s] rx: [%s]\n", peer, tx, rx);

	peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;

	return 0;
}

bool chipvpn_peer_set_allow(chipvpn_peer_t *peer, const char *address, uint8_t prefix) {
	if(!chipvpn_address_set_ip(&peer->config.allow, address)) {
		return false;
	}
	peer->config.allow.prefix = prefix;
	return true;
}

bool chipvpn_peer_set_address(chipvpn_peer_t *peer, const char *address, uint16_t port) {
	if(!chipvpn_address_set_ip(&peer->config.address, address)) {
		return false;
	}
	peer->config.address.port = port;
	return true;
}

bool chipvpn_peer_set_key(chipvpn_peer_t *peer, const char *key) {
	sha256(key, strlen(key), peer->config.key, sizeof(peer->config.key));

	return true;
}

bool chipvpn_peer_set_onconnect(chipvpn_peer_t *peer, const char *command) {
	peer->config.onconnect = strdup(command);
	return true;
}

bool chipvpn_peer_set_onping(chipvpn_peer_t *peer, const char *command) {
	peer->config.onping = strdup(command);
	return true;
}

bool chipvpn_peer_set_ondisconnect(chipvpn_peer_t *peer, const char *command) {
	peer->config.ondisconnect = strdup(command);
	return true;
}

chipvpn_peer_t *chipvpn_peer_get_by_key(chipvpn_list_t *peers, char *key) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(memcmp(key, peer->config.key, sizeof(peer->config.key)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_keyhash(chipvpn_list_t *peers, char *key) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		char current[32];
		
		hmac_sha256(
			peer->config.key, 
			sizeof(peer->config.key),
			"#CHIPVPN_KEYHASH",
			16,
			current, 
			sizeof(current)
		);

		if(memcmp(key, current, sizeof(current)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_allowip(chipvpn_list_t *peers, chipvpn_address_t *ip) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_address_cidr_match(ip, &peer->config.allow)) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_session(chipvpn_list_t *peers, uint32_t session) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		
		if(session == peer->session) {
			return peer;
		}
	}
	return NULL;
}

void chipvpn_peer_set_state(chipvpn_peer_t *peer, chipvpn_peer_state_e state) {
	if(peer->state != state) {
		switch(state) {
			case PEER_CONNECTED: {
				if(peer->config.onconnect) {
					chipvpn_peer_run_command(peer, peer->config.onconnect);
				}
			}
			break;
			case PEER_DISCONNECTED: {
				if(peer->config.ondisconnect) {
					chipvpn_peer_run_command(peer, peer->config.ondisconnect);
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
	char keyhash[64 + 1];
	char address[16];
	char port[16];

	if(peer) {
		sprintf(tx, "%lu", peer->tx);
		sprintf(rx, "%lu", peer->rx);

		char keyhash_buffer[32];
		hmac_sha256(
			peer->config.key, 
			sizeof(peer->config.key),
			"#CHIPVPN_KEYHASH",
			16,
			keyhash_buffer, 
			sizeof(keyhash_buffer)
		);
		for(int i = 0; i < 32; i++) {
			sprintf(&keyhash[i * 2], "%02x", keyhash_buffer[i] & 0xff);
		}

		strcpy(address, chipvpn_address_to_char(&peer->address));
		sprintf(port, "%u", peer->address.port);
	}

	char *result1 = str_replace(command, "%gateway%", gateway);
	char *result2 = str_replace(result1, "%gatewaydev%", dev);
	char *result3 = str_replace(result2, "%tx%", tx);
	char *result4 = str_replace(result3, "%rx%", rx);
	char *result5 = str_replace(result4, "%keyhash%", keyhash);
	char *result6 = str_replace(result5, "%paddr%", address);
	char *result7 = str_replace(result6, "%pport%", port);
	if(system(result7) == 0) {
		chipvpn_log_append("%s\n", result7);
	}
	free(result1);
	free(result2);
	free(result3);
	free(result4);
	free(result5);
	free(result6);
	free(result7);
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);

	if(peer->config.onconnect) {
		free(peer->config.onconnect);
	}

	if(peer->config.onping) {
		free(peer->config.onping);
	}

	if(peer->config.ondisconnect) {
		free(peer->config.ondisconnect);
	}

	free(peer);
}