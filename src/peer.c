#include "peer.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <endian.h>
#include "chipvpn.h"
#include "packet.h"
#include "device.h"
#include "util.h"
#include "base64.h"
#include "util.h"
#include "noise.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	peer->type = PEER_PERMANENT;

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));
	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);

	return peer;
}

int chipvpn_peer_send_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr) {
	chipvpn_packet_auth_t packet;
	memset(&packet, 0, sizeof(packet));

	if(!chipvpn_noise_produce_connect(peer, device, &packet)) {
		chipvpn_log_append("noise handshake failed\n");
		return 0;
	}

	return chipvpn_socket_write(udp->socket, &packet, sizeof(packet), addr);
}

int chipvpn_peer_recv_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_packet_auth_t *packet, chipvpn_address_t *addr) {
	/* authenticated */

	if(!chipvpn_peer_send_auth_reply(peer, device, udp, addr)) {
		chipvpn_log_append("noise handshake failed\n");
		return 0;
	}

	if(!chipvpn_noise_begin_session(peer, false)) {
		chipvpn_log_append("peer failed to create session\n");
		return 0;
	}

	/* expects a keepalive packet from initiator */
	peer->address = *addr;

	peer->ack_state = PEER_ACK_OWE_TX;
	peer->next_ack = chipvpn_get_time() + 15000;

	peer->last_check = 0;
	peer->last_handshake = chipvpn_get_time();

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->handshake.inbound_id, peer->handshake.outbound_id);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	chipvpn_peer_set_state(peer, PEER_CONNECTED);

	return 0;
}

int chipvpn_peer_send_auth_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr) {
	chipvpn_packet_auth_reply_t packet;
	memset(&packet, 0, sizeof(packet));
	
	if(!chipvpn_noise_produce_reply(peer, device, &packet)) {
		chipvpn_log_append("noise handshake failed\n");
		return 0;
	}

	return chipvpn_socket_write(udp->socket, &packet, sizeof(packet), addr);
}

int chipvpn_peer_recv_auth_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_packet_auth_reply_t *packet, chipvpn_address_t *addr) {
	/* authenticated */

	if(!chipvpn_noise_begin_session(peer, true)) {
		chipvpn_log_append("peer failed to create session\n");
		return 0;
	}

	/* responder expects a keepalive packet (immediately) */
	peer->address = *addr;

	peer->ack_state = PEER_ACK_OWE_RX;
	peer->next_ack = chipvpn_get_time();

	peer->last_check = 0;
	peer->last_handshake = chipvpn_get_time();

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->handshake.inbound_id, peer->handshake.outbound_id);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	chipvpn_peer_set_state(peer, PEER_CONNECTED);

	/* promote peer session immediately from next_session to session */
	chipvpn_peer_session_promote(peer);

	return 0;
}

int chipvpn_peer_send_keepalive(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp) {
	chipvpn_log_append("%p says: sent keepalive packet\n", peer);

	peer->session.counter++;

	chipvpn_packet_data_t header = {
		.header.type = CHIPVPN_PACKET_DATA,
		.session     = htole32(peer->session.outbound.id),
		.counter     = htole64(peer->session.counter)
	};

	uint8_t empty[1] = {0};
	uint8_t mac[CHACHA20_POLY1305_ENC_LEN(0)];

	bool success = chipvpn_crypto_chacha20_poly1305_encrypt(
		peer->session.outbound.key, 
		empty, 
		0, 
		peer->session.counter, 
		NULL, 
		0,
		mac
	);

	if(!success) {
		chipvpn_log_append("%p says: unable to encrypt payload\n", peer);
		return 0;
	}

	if(peer->ack_state == PEER_ACK_OWE_RX) {
		peer->ack_state = PEER_ACK_IDLE;
	}

	chipvpn_socket_vector_t vector[] = {
		{ .data = &header, .size = sizeof(header) }, 
		{ .data = mac, .size = sizeof(mac) }
	};

	return chipvpn_socket_write_vector(udp->socket, vector, 2, &peer->address);
}

int chipvpn_peer_recv_keepalive(chipvpn_peer_t *peer) {
	chipvpn_log_append("%p says: received keepalive packet\n", peer);
	if(peer->ack_state == PEER_ACK_OWE_TX) {
		peer->ack_state = PEER_ACK_IDLE;
	}

	return 0;
}


void chipvpn_peer_reset_session(chipvpn_peer_t *peer) {
	peer->tx = 0llu;
	peer->rx = 0llu;

	chipvpn_secure_zero(&peer->handshake, sizeof(peer->handshake));

	chipvpn_secure_zero(&peer->prev_session, sizeof(peer->prev_session));
	chipvpn_secure_zero(&peer->session, sizeof(peer->session));
	chipvpn_secure_zero(&peer->next_session, sizeof(peer->next_session));

	chipvpn_log_append("%p says: session cleared\n", peer);
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

bool chipvpn_peer_set_public_key(chipvpn_peer_t *peer, chipvpn_device_t *device, const char *key) {
	return b64_decode((uint8_t*)key, strlen(key), peer->config.public) == CURVE25519_KEY_SIZE;
}

bool chipvpn_peer_set_psk(chipvpn_peer_t *peer, const char *key) {
	return b64_decode((uint8_t*)key, strlen(key), peer->config.psk) == BLAKE2S_HASH_SIZE;
}

bool chipvpn_peer_set_onconnect(chipvpn_peer_t *peer, const char *command) {
	peer->config.onconnect = chipvpn_strdup(command);
	return true;
}

bool chipvpn_peer_set_ondisconnect(chipvpn_peer_t *peer, const char *command) {
	peer->config.ondisconnect = chipvpn_strdup(command);
	return true;
}

void chipvpn_peer_session_promote(chipvpn_peer_t *peer) {
	chipvpn_log_append("%p says: promote session\n", peer);

	memcpy(&peer->prev_session, &peer->session, sizeof(peer->session));
	memset(&peer->session, 0, sizeof(peer->session));
	memcpy(&peer->session, &peer->next_session, sizeof(peer->next_session));
	memset(&peer->next_session, 0, sizeof(peer->next_session));
}

void chipvpn_peer_set_state(chipvpn_peer_t *peer, chipvpn_peer_state_e state) {
	if(peer->state != state) {
		peer->state = state;

		switch(state) {
			case PEER_CONNECTED: {
				if(peer->config.onconnect) {
					chipvpn_peer_run_command(peer, peer->config.onconnect);
				}
			}
			break;
			case PEER_DISCONNECTED: {
				chipvpn_peer_reset_session(peer);
				if(peer->config.ondisconnect) {
					chipvpn_peer_run_command(peer, peer->config.ondisconnect);
				}
			}
			break;
		}
	}
}

void chipvpn_peer_run_command(chipvpn_peer_t *peer, const char *command) {
	char tx[16];
	char rx[16];
	char address[16];
	char port[16];

	if(peer) {
		sprintf(tx, "%lu", peer->tx);
		sprintf(rx, "%lu", peer->rx);

		strcpy(address, chipvpn_address_to_char(&peer->address));
		sprintf(port, "%u", peer->address.port);
	}

	char *result1 = chipvpn_str_replace(command, "%tx%", tx);
	char *result2 = chipvpn_str_replace(result1, "%rx%", rx);
	char *result3 = chipvpn_str_replace(result2, "%paddr%", address);
	char *result4 = chipvpn_str_replace(result3, "%pport%", port);

	if(system(result4) == 0) {
		chipvpn_log_append("%s\n", result4);
	}
	
	free(result1);
	free(result2);
	free(result3);
	free(result4);
}

void chipvpn_peer_service(chipvpn_list_t *peers, chipvpn_device_t *device, chipvpn_udp_t *udp) {
	/* peer lifecycle service */
	uint64_t now = chipvpn_get_time();

	chipvpn_list_node_t *p = chipvpn_list_begin(peers);

	while(p != chipvpn_list_end(peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		p = chipvpn_list_next(p);

		if(now > peer->last_check + 2000) {
			peer->last_check = now;

			if(peer->state == PEER_CONNECTED) {
				char tx[128];
				char rx[128];
				strcpy(tx, chipvpn_format_bytes(peer->tx));
				strcpy(rx, chipvpn_format_bytes(peer->rx));

				chipvpn_log_append("%p says: peer alive, last handshake: [%lu] second(s)\n", peer, (now - peer->last_handshake) / 1000);
				chipvpn_log_append("%p says: tx: [%s] rx: [%s]\n", peer, tx, rx);

				uint64_t next_rekey      = peer->last_handshake + CHIPVPN_REKEY_AFTER_TIME;
				uint64_t next_disconnect = peer->last_handshake + CHIPVPN_REJECT_AFTER_TIME;

				/* after CHIPVPN_REJECT_AFTER_TIME, clear and zero all sessions */
				if(GTEQ(now, next_disconnect)) {
					chipvpn_log_append("%p says: peer disconnected\n", peer);
					chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
				}

				/* after CHIPVPN_REKEY_AFTER_TIME and before CHIPVPN_REJECT_AFTER_TIME */
				if(GTEQ(now, next_rekey) && LT(now, next_disconnect)) {
					chipvpn_log_append("%p says: rekeying to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);
					chipvpn_peer_send_connect(peer, device, udp, &peer->address);
				}

				/* after next_ack and before CHIPVPN_REKEY_AFTER_TIME, force a rekey immediately */
				if(GTEQ(now, peer->next_ack) && LT(now, next_rekey) && peer->ack_state == PEER_ACK_OWE_TX) {
					chipvpn_log_append("%p says: rekeying to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);
					chipvpn_peer_send_connect(peer, device, udp, &peer->address);
				}

				/* after next_ack and before CHIPVPN_REKEY_AFTER_TIME */
				if(GTEQ(now, peer->next_ack) && LT(now, next_rekey) && peer->ack_state == PEER_ACK_OWE_RX) {
					chipvpn_peer_send_keepalive(peer, device, udp);
				}
			} else if(peer->state == PEER_DISCONNECTED) {
				/* attempt to connect to peer as initiator */
				if(peer->config.address.ip > 0) {
					chipvpn_log_append("%p says: connecting to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->config.address), peer->config.address.port);
					chipvpn_peer_send_connect(peer, device, udp, &peer->config.address);
				}

				/* remove peer if it is ephemeral and has timeout */
				if(peer->type == PEER_EPHEMERAL && GT(now, peer->last_handshake + CHIPVPN_REJECT_AFTER_TIME)) {
					chipvpn_log_append("%p says: ephemeral peer is removed\n", peer);
					chipvpn_list_remove(&peer->node);
					chipvpn_peer_free(peer);
					continue;
				}
			}
		}
	}
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);

	if(peer->config.onconnect) {
		free(peer->config.onconnect);
	}

	if(peer->config.ondisconnect) {
		free(peer->config.ondisconnect);
	}

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	free(peer);
}