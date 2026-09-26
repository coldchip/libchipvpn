#include "peer.h"
#include <stdlib.h>
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

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	peer->type = PEER_PERMANENT;

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);

	chipvpn_firewall_reset(&peer->config.firewall);

	return peer;
}

int chipvpn_peer_send_wg_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr) {
	chipvpn_wg_packet_auth_t packet;
	chipvpn_secure_zero(&packet, sizeof(packet));

	packet.header.type = CHIPVPN_PACKET_AUTH; // Handshake Initiation

	// Generate a secure 32-bit random integer for our session ID
	chipvpn_secure_random((uint8_t*)&peer->inbound.session, sizeof(peer->inbound.session));
	packet.sender_index = htole32(peer->inbound.session); 

	chipvpn_init_noise(peer->chain_key, peer->hash_key, peer->config.public);

	chipvpn_secure_random(peer->ephemeral_private, sizeof(peer->ephemeral_private));
	peer->ephemeral_private[0] &= 248;
	peer->ephemeral_private[31] = (peer->ephemeral_private[31] & 127) | 64;
	uint8_t basepoint[CURVE25519_KEY_SIZE] = {9};
	curve25519(peer->ephemeral_public, peer->ephemeral_private, basepoint);

	// Write to packet
	memcpy(packet.ephemeral_public, peer->ephemeral_public, sizeof(peer->ephemeral_public));

	chipvpn_blake2s_kdf1(peer->chain_key, peer->chain_key, peer->ephemeral_public, sizeof(peer->ephemeral_public));
	chipvpn_blake2s_concat(peer->hash_key, peer->ephemeral_public, sizeof(peer->ephemeral_public));

	uint8_t key[CHACHA20_KEY_SIZE];
	curve25519(peer->dh_es, peer->ephemeral_private, peer->config.public);
	chipvpn_blake2s_kdf2(peer->chain_key, key, peer->chain_key, peer->dh_es, sizeof(peer->dh_es));

	memcpy(packet.static_public, device->public, sizeof(device->public));

	chipvpn_encrypt_and_mix(peer->hash_key, key, packet.static_public, 32, packet.static_public_mac);

	curve25519(peer->dh_ss, device->private, peer->config.public);
	chipvpn_blake2s_kdf2(peer->chain_key, key, peer->chain_key, peer->dh_ss, sizeof(peer->dh_ss));

	chipvpn_tai64n(packet.timestamp);

	chipvpn_encrypt_and_mix(peer->hash_key, key, packet.timestamp, sizeof(packet.timestamp), packet.timestamp_mac);

	chipvpn_compute_macs(&packet, offsetof(chipvpn_wg_packet_auth_t, mac1), packet.mac1, packet.mac2, peer->config.public);

	return chipvpn_socket_write(udp->socket, &packet, sizeof(packet), addr);
}

int chipvpn_peer_recv_wg_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_wg_packet_auth_t *packet, chipvpn_address_t *addr) {
	uint8_t key[BLAKE2S_HASH_SIZE] = {0};

	// (Ci,k) := Kdf2(Ci,DH(Sprivi,Spubr)) (SS)
	chipvpn_blake2s_kdf2(peer->chain_key, key, peer->chain_key, peer->dh_ss, sizeof(peer->dh_ss));

	if(!chipvpn_decrypt_and_mix(peer->hash_key, key, packet->timestamp, sizeof(packet->timestamp), packet->timestamp_mac)) {
		chipvpn_log_append("invalid mac\n");
		return 0;
	}

	peer->outbound.session = le32toh(packet->sender_index);

	chipvpn_secure_random(peer->ephemeral_private, sizeof(peer->ephemeral_private));
	peer->ephemeral_private[0] &= 248;
	peer->ephemeral_private[31] = (peer->ephemeral_private[31] & 127) | 64;

	// calculate public key
	uint8_t basepoint[CURVE25519_KEY_SIZE] = {9};
	curve25519(peer->ephemeral_public, peer->ephemeral_private, basepoint);

	chipvpn_blake2s_kdf1(peer->chain_key, peer->chain_key, peer->ephemeral_public, sizeof(peer->ephemeral_public));
	chipvpn_blake2s_concat(peer->hash_key, peer->ephemeral_public, sizeof(peer->ephemeral_public));

	curve25519(peer->dh_ee, peer->ephemeral_private, packet->ephemeral_public);
	chipvpn_blake2s_kdf1(peer->chain_key, peer->chain_key, peer->dh_ee, sizeof(peer->dh_ee));

	curve25519(peer->dh_es, peer->ephemeral_private, peer->config.public);
	chipvpn_blake2s_kdf1(peer->chain_key, peer->chain_key, peer->dh_es, sizeof(peer->dh_es));

	chipvpn_peer_send_wg_reply(peer, device, udp, addr);

	uint8_t dummy[1] = {0};
	chipvpn_blake2s_kdf2(peer->inbound.key, peer->outbound.key, peer->chain_key, dummy, 0);

	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	chipvpn_peer_set_state(peer, PEER_CONNECTED);

	/* reset the bitmap */
	chipvpn_bitmap_reset(&peer->bitmap);

	peer->address = *addr;
	peer->timestamp = 0;
	peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;
	peer->tx = 0llu;
	peer->rx = 0llu;
	peer->last_check = 0llu;
	peer->counter = 0llu;

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->inbound.session, peer->outbound.session);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	return 0;
}

int chipvpn_peer_send_wg_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr) {
	chipvpn_wg_packet_auth_resp_t reply;
	chipvpn_secure_zero(&reply, sizeof(reply));
	reply.header.type = CHIPVPN_PACKET_AUTH_REPLY; // Handshake Response
	reply.receiver_index = htole32(peer->outbound.session); // Send back the client's ID
	chipvpn_secure_random((uint8_t*)&peer->inbound.session, sizeof(peer->inbound.session));
	reply.sender_index = htole32(peer->inbound.session); 

	uint8_t tau[BLAKE2S_HASH_SIZE] = {0};
	uint8_t psk[CHACHA20_KEY_SIZE] = {0};
	uint8_t empty[1] = {0};
	uint8_t key1[CHACHA20_KEY_SIZE] = {0};

	chipvpn_blake2s_kdf3(peer->chain_key, tau, key1, peer->chain_key, psk, sizeof(psk));
	chipvpn_blake2s_concat(peer->hash_key, tau, sizeof(tau));

	chipvpn_encrypt_and_mix(peer->hash_key, key1, empty, 0, reply.empty_mac);

	memcpy(reply.ephemeral_public, peer->ephemeral_public, 32);

	chipvpn_compute_macs(&reply, offsetof(chipvpn_wg_packet_auth_resp_t, mac1), reply.mac1, reply.mac2, peer->config.public);

	return chipvpn_socket_write(udp->socket, &reply, sizeof(reply), addr);
}

int chipvpn_peer_recv_wg_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_wg_packet_auth_resp_t *packet, chipvpn_address_t *addr) {
	if(le32toh(packet->receiver_index) != peer->inbound.session) {
		chipvpn_log_append("Dropped Handshake Response: Session ID mismatch. %u %u\n", le32toh(packet->receiver_index), peer->inbound.session);
		return 0;
	}

	peer->outbound.session = le32toh(packet->sender_index);

	chipvpn_blake2s_kdf1(peer->chain_key, peer->chain_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));
	chipvpn_blake2s_concat(peer->hash_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));

	uint8_t dh_ee[CURVE25519_KEY_SIZE];
	curve25519(dh_ee, peer->ephemeral_private, packet->ephemeral_public);
	chipvpn_blake2s_kdf1(peer->chain_key, peer->chain_key, dh_ee, sizeof(dh_ee));

	uint8_t dh_se[CURVE25519_KEY_SIZE];
	curve25519(dh_se, device->private, packet->ephemeral_public);
	chipvpn_blake2s_kdf1(peer->chain_key, peer->chain_key, dh_se, sizeof(dh_se));

	uint8_t tau[BLAKE2S_HASH_SIZE] = {0};
	uint8_t key[CHACHA20_KEY_SIZE] = {0};
	uint8_t psk[CHACHA20_KEY_SIZE] = {0};

	chipvpn_blake2s_kdf3(peer->chain_key, tau, key, peer->chain_key, psk, sizeof(psk));
	chipvpn_blake2s_concat(peer->hash_key, tau, sizeof(tau));

	uint8_t dummy[1] = {0};
	if (!chipvpn_decrypt_and_mix(peer->hash_key, key, dummy, 0, packet->empty_mac)) {
		chipvpn_log_append("invalid mac\n");
		return 0;
	}

	chipvpn_blake2s_kdf2(peer->outbound.key, peer->inbound.key, peer->chain_key, dummy, 0);

	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	chipvpn_peer_set_state(peer, PEER_CONNECTED);
	chipvpn_bitmap_reset(&peer->bitmap);

	peer->address = *addr;
	peer->timestamp = 0;
	peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;
	peer->tx = 0llu;
	peer->rx = 0llu;
	peer->last_check = 0llu;
	peer->counter = 0llu;

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->inbound.session, peer->outbound.session);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	return 0;
}

int chipvpn_peer_send_ping(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp) {
	peer->counter++;

	if(peer->config.onping) {
		chipvpn_peer_run_command(peer, peer->config.onping);
	}

	chipvpn_packet_data_t header = {
		.header.type = CHIPVPN_PACKET_DATA,
		.session     = htole32(peer->outbound.session),
		.counter     = htole64(peer->counter)
	};

	uint8_t empty[1] = {0};
	uint8_t mac[16];

	if(!chipvpn_peer_encrypt_payload(peer, empty, 0, peer->counter, mac)) {
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
	chipvpn_secure_zero(peer->chain_key, sizeof(peer->chain_key));
	chipvpn_secure_zero(peer->hash_key, sizeof(peer->hash_key));
	chipvpn_secure_zero(peer->ephemeral_public, sizeof(peer->ephemeral_public));
	chipvpn_secure_zero(peer->ephemeral_private, sizeof(peer->ephemeral_private));

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
	bool ret = b64_decode((uint8_t*)key, strlen(key), peer->config.public) > 0;
	curve25519(peer->dh_ss, device->private, peer->config.public);
	return ret;
}

bool chipvpn_peer_set_onconnect(chipvpn_peer_t *peer, const char *command) {
	peer->config.onconnect = chipvpn_strdup(command);
	return true;
}

bool chipvpn_peer_set_onping(chipvpn_peer_t *peer, const char *command) {
	peer->config.onping = chipvpn_strdup(command);
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

chipvpn_peer_t *chipvpn_peer_get_by_inbound_session(chipvpn_list_t *peers, uint32_t session) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		
		if(session == peer->inbound.session) {
			return peer;
		}
	}
	return NULL;
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
	char gateway[16];
	char dev[16];
	if(!chipvpn_get_gateway(gateway, dev)) {

	}

	char tx[16];
	char rx[16];
	char keyhash[64 + 1];
	char address[16];
	char port[16];

	if(peer) {
		sprintf(tx, "%lu", peer->tx);
		sprintf(rx, "%lu", peer->rx);

		memset(keyhash, 0, sizeof(keyhash));
		for(int i = 0; i < 32; i++) {
			sprintf(&keyhash[i * 2], "%02x", peer->config.public[i] & 0xff);
		}

		strcpy(address, chipvpn_address_to_char(&peer->address));
		sprintf(port, "%u", peer->address.port);
	}

	char *result1 = chipvpn_str_replace(command, "%gateway%", gateway);
	char *result2 = chipvpn_str_replace(result1, "%gatewaydev%", dev);
	char *result3 = chipvpn_str_replace(result2, "%tx%", tx);
	char *result4 = chipvpn_str_replace(result3, "%rx%", rx);
	char *result5 = chipvpn_str_replace(result4, "%keyhash%", keyhash);
	char *result6 = chipvpn_str_replace(result5, "%paddr%", address);
	char *result7 = chipvpn_str_replace(result6, "%pport%", port);

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

void chipvpn_peer_service(chipvpn_list_t *peers, chipvpn_device_t *device, chipvpn_udp_t *udp) {
	/* peer lifecycle service */
	uint64_t now = chipvpn_get_time();

	chipvpn_list_node_t *p = chipvpn_list_begin(peers);

	while(p != chipvpn_list_end(peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		p = chipvpn_list_next(p);

		if(now - peer->last_check > CHIPVPN_PEER_PING) {
			peer->last_check = now;

			if(peer->state == PEER_CONNECTED) {
				/* ping peers */
				chipvpn_peer_send_ping(peer, device, udp);

				if(now > peer->timeout) {
					chipvpn_log_append("%p says: peer disconnected\n", peer);
					chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
				}
			} else if(peer->state == PEER_DISCONNECTED) {
				/* attempt to connect to peer */
				if(peer->config.address.ip > 0) {
					chipvpn_log_append("%p says: connecting to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->config.address), peer->config.address.port);
					//chipvpn_peer_send_connect(peer, device, udp, &peer->config.address, true);
					chipvpn_peer_send_wg_connect(peer, device, udp, &peer->config.address);
				}

				if(peer->type == PEER_EPHEMERAL && now > peer->timeout) {
					chipvpn_log_append("%p says: ephemeral peer is removed\n", peer);
					chipvpn_list_remove(&peer->node);
					chipvpn_peer_free(peer);
					continue;
				}
			}
		}
	}
}

bool chipvpn_peer_encrypt_payload(chipvpn_peer_t *peer, uint8_t *data, int size, uint64_t counter, uint8_t *mac) {
	return chipvpn_crypto_chacha20_poly1305_encrypt(
		peer->outbound.key, 
		data, 
		size, 
		counter, 
		NULL, 
		0,
		mac
	);
}

bool chipvpn_peer_decrypt_payload(chipvpn_peer_t *peer, uint8_t *data, int size, uint64_t counter, uint8_t *mac) {
	return chipvpn_crypto_chacha20_poly1305_decrypt(
		peer->inbound.key, 
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

	if(peer->config.onping) {
		free(peer->config.onping);
	}

	if(peer->config.ondisconnect) {
		free(peer->config.ondisconnect);
	}

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	free(peer);
}