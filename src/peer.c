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
#include "curve25519.h"
#include "chacha20poly1305.h"
#include "chacha20.h"
#include "hmac_blake2s.h"
#include "firewall.h"
#include "log.h"
#include "util.h"
#include "noise.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	peer->type = PEER_PERMANENT;

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));
	chipvpn_firewall_reset(&peer->config.firewall);
	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);

	return peer;
}

int chipvpn_peer_send_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr) {
	chipvpn_packet_auth_t packet;
	
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

	peer->last_tx_time = 0;
	peer->last_rx_time = 0;
	peer->address = *addr;
	peer->last_handshake = chipvpn_get_time();

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->handshake.inbound_id, peer->handshake.outbound_id);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	chipvpn_peer_set_state(peer, PEER_CONNECTED);

	return 0;
}

int chipvpn_peer_send_auth_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr) {
	chipvpn_packet_auth_reply_t packet;
	
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

	peer->last_tx_time = 0;
	peer->last_rx_time = 0;
	peer->address = *addr;
	peer->last_handshake = chipvpn_get_time();

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->handshake.inbound_id, peer->handshake.outbound_id);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	chipvpn_peer_set_state(peer, PEER_CONNECTED);

	chipvpn_peer_session_promote(peer);
	chipvpn_peer_send_keepalive(peer, device, udp);

	return 0;
}

int chipvpn_peer_send_keepalive(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp) {
	peer->session.counter++;

	chipvpn_packet_data_t header = {
		.header.type = CHIPVPN_PACKET_DATA,
		.session     = htole32(peer->session.outbound.id),
		.counter     = htole64(peer->session.counter)
	};

	uint8_t empty[1] = {0};
	uint8_t mac[CHACHA20_POLY1305_ENC_LEN(0)];

	if(!chipvpn_peer_encrypt_payload(&peer->session, empty, 0, peer->session.counter, mac)) {
		chipvpn_log_append("%p says: unable to encrypt payload\n", peer);
		return 0;
	}

	chipvpn_socket_vector_t vector[] = {
		{ .data = &header, .size = sizeof(header) }, 
		{ .data = mac, .size = sizeof(mac) }
	};

	return chipvpn_socket_write_vector(udp->socket, vector, 2, &peer->address);
}


void chipvpn_peer_reset_session(chipvpn_peer_t *peer) {
	peer->tx = 0llu;
	peer->rx = 0llu;

	chipvpn_secure_zero(&peer->handshake, sizeof(peer->handshake));
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

chipvpn_peer_t *chipvpn_peer_get_by_public_key(chipvpn_list_t *peers, uint8_t *public) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_secure_memcmp(public, peer->config.public, sizeof(peer->config.public)) == 0) {
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

chipvpn_peer_t *chipvpn_peer_by_handshake(chipvpn_list_t *peers, uint32_t session_id) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(session_id == peer->handshake.inbound_id) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_by_session(chipvpn_list_t *peers, chipvpn_peer_session_t **session, uint32_t session_id) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(session_id == peer->prev_session.inbound.id) {
			if(session) {
				*session = &peer->prev_session;
			}
			return peer;
		}

		if(session_id == peer->session.inbound.id) {
			if(session) {
				*session = &peer->session;
			}
			return peer;
		}

		if(session_id == peer->next_session.inbound.id) {
			if(session) {
				*session = &peer->next_session;
			}
			return peer;
		}
	}
	return NULL;
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

		chipvpn_peer_reset_session(peer);

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

		if(now > peer->last_check + 1000) {
			peer->last_check = now;

			if(peer->state == PEER_CONNECTED) {
				/* ping peers */

				char tx[128];
				char rx[128];
				strcpy(tx, chipvpn_format_bytes(peer->tx));
				strcpy(rx, chipvpn_format_bytes(peer->rx));

				chipvpn_log_append("%p says: peer alive, last handshake: %lu sec\n", peer, (now - peer->last_handshake) / 1000);
				chipvpn_log_append("%p says: tx: [%s] rx: [%s]\n", peer, tx, rx);

				if(now > peer->last_tx_time + 15000 && peer->last_tx_time != 0) {
					peer->last_handshake = 1;
				}

				if(now > peer->last_rx_time + 10000 && peer->last_rx_time != 0) {
					chipvpn_peer_send_keepalive(peer, device, udp);
					peer->last_rx_time = 0;
				}

				if(now > (peer->last_handshake + CHIPVPN_PEER_REKEY)) {
					chipvpn_log_append("%p says: rekeying to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);
					chipvpn_peer_send_connect(peer, device, udp, &peer->address);
				}

				if(now > (peer->last_handshake + CHIPVPN_PEER_REKEY + CHIPVPN_PEER_TIMEOUT)) {
					chipvpn_log_append("%p says: peer disconnected\n", peer);
					chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
				}
			} else if(peer->state == PEER_DISCONNECTED) {
				/* attempt to connect to peer */
				if(peer->config.address.ip > 0) {
					chipvpn_log_append("%p says: connecting to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->config.address), peer->config.address.port);
					chipvpn_peer_send_connect(peer, device, udp, &peer->config.address);
				}

				if(peer->type == PEER_EPHEMERAL && now > (peer->last_handshake + CHIPVPN_PEER_REKEY + CHIPVPN_PEER_TIMEOUT)) {
					chipvpn_log_append("%p says: ephemeral peer is removed\n", peer);
					chipvpn_list_remove(&peer->node);
					chipvpn_peer_free(peer);
					continue;
				}
			}
		}
	}
}

bool chipvpn_peer_encrypt_payload(chipvpn_peer_session_t *session, uint8_t *data, size_t size, uint64_t counter, uint8_t *mac) {
	return chipvpn_crypto_chacha20_poly1305_encrypt(
		session->outbound.key, 
		data, 
		size, 
		counter, 
		NULL, 
		0,
		mac
	);
}

bool chipvpn_peer_decrypt_payload(chipvpn_peer_session_t *session, uint8_t *data, size_t size, uint64_t counter, uint8_t *mac) {
	return chipvpn_crypto_chacha20_poly1305_decrypt(
		session->inbound.key, 
		data, 
		size, 
		counter, 
		NULL, 
		0, 
		mac
	);
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