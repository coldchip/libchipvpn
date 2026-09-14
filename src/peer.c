#include "peer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "packet.h"
#include "device.h"
#include "util.h"
#include "sha256.h"
#include "base64.h"
#include "hmac_sha256.h"
#include "hkdf_sha256.h"
#include "curve25519.h"
#include "chacha20poly1305.h"
#include "chacha20.h"
#include "dh.h"
#include "firewall.h"
#include "log.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	chipvpn_peer_reset_session(peer);

	chipvpn_firewall_reset(&peer->config.firewall);

	return peer;
}

int chipvpn_peer_send_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr, bool ack) {
	chipvpn_packet_auth_t packet = {
		.header.type = CHIPVPN_PACKET_AUTH,
		.version = htonl(CHIPVPN_PROTOCOL_VERSION),
		.timestamp = htonll(chipvpn_get_time()),
		.ack = ack
	};

	// Generate curve25519 keys
	chipvpn_secure_random(peer->ephemeral_private, sizeof(peer->ephemeral_private));
	uint8_t curve_basepoint[CURVE25519_KEY_SIZE] = {9};

	// generate ephemeral public key
	curve25519(peer->ephemeral_public, peer->ephemeral_private, curve_basepoint);

	// compute dh-es
	curve25519(peer->dh_es, peer->ephemeral_private, peer->config.public);

	// copy curve25519 public key to packet
	memcpy(packet.ephemeral_public, peer->ephemeral_public, sizeof(peer->ephemeral_public));

	/* copy keyhash */
	memcpy(packet.static_public, device->public, sizeof(device->public));
	memset(packet.sign, 0, sizeof(packet.sign));

	// sign packet
	chipvpn_dh_sign(
		peer->dh_es,
		peer->dh_ss, 
		NULL,
		NULL,
		(uint8_t*)&packet,
		sizeof(packet),
		packet.sign
	);

	// encrypt static_public
	chipvpn_dh_xcrypt(
		peer->dh_es, 
		NULL,
		NULL,
		NULL,
		packet.static_public, 
		sizeof(packet.static_public)
	);

	peer->half_auth = true;

	return chipvpn_socket_write(udp->socket, &packet, sizeof(packet), addr);
}

int chipvpn_peer_recv_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_packet_auth_t *packet, chipvpn_address_t *addr) {
	if(ntohl(packet->version) != CHIPVPN_PROTOCOL_VERSION) {
		chipvpn_log_append("invalid protocol version\n");
		return 0;
	}

	uint8_t sign[SHA256_HASH_SIZE];
	uint8_t computed_sign[SHA256_HASH_SIZE];
	memcpy(sign, packet->sign, sizeof(packet->sign));
	memset(packet->sign, 0, sizeof(packet->sign));

	chipvpn_dh_sign(
		peer->dh_se,
		peer->dh_ss,
		NULL,
		NULL,
		(uint8_t*)packet,
		sizeof(chipvpn_packet_auth_t),
		computed_sign
	);

	if(chipvpn_secure_memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
		chipvpn_log_append("invalid sign\n");
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

	if(packet->ack) {
		chipvpn_log_append("%p says: peer requested auth acknowledgement\n", peer);
		chipvpn_peer_send_connect(peer, device, udp, addr, false);
	}

	if(!peer->half_auth) {
		chipvpn_log_append("peer skipped the first half of the authentication process\n");
		return 0;
	}

	// check randomness distrubution of packet's ephemeral public
	if(!chipvpn_check_key_randomness(packet->ephemeral_public, sizeof(packet->ephemeral_public))) {
		chipvpn_log_append("peer has repeating or highly predictable ephemeral public key\n");
		return 0;
	}

	// reject if peer has same curve25519 public key
	if(chipvpn_secure_memcmp(packet->ephemeral_public, peer->ephemeral_public, sizeof(packet->ephemeral_public)) == 0) {
		chipvpn_log_append("peer has the same curve25519 keys\n");
		return 0;
	}

	/* peer has been authenticated */
	curve25519(peer->dh_ee, peer->ephemeral_private, packet->ephemeral_public);

	// Figure out roles (client or server)
	int role = memcmp(device->public, peer->config.public, sizeof(peer->config.public)) > 0;

	SECURE32 uint8_t dh_shared[SHA256_HASH_SIZE];
	chipvpn_dh_chain(
		peer->dh_ee, 
		peer->dh_ss, 
		role ? peer->dh_es : peer->dh_se, 
		role ? peer->dh_se : peer->dh_es, 
		CHIPVPN_MASTER_TAG,
		sizeof(CHIPVPN_MASTER_TAG) - 1, 
		dh_shared
	);

	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	
	// Derive keys
	hkdf_sha256(
		NULL, 
		0, 
		dh_shared,
		sizeof(dh_shared),
		CHIPVPN_DIRECTIONAL_KEY_A,
		sizeof(CHIPVPN_DIRECTIONAL_KEY_A) - 1,
		role ? peer->inbound.key : peer->outbound.key,
		sizeof(peer->inbound.key)
	);

	hkdf_sha256(
		NULL, 
		0, 
		dh_shared,
		sizeof(dh_shared),
		CHIPVPN_DIRECTIONAL_KEY_B,
		sizeof(CHIPVPN_DIRECTIONAL_KEY_B) - 1,
		role ? peer->outbound.key : peer->inbound.key,
		sizeof(peer->outbound.key)
	);

	hkdf_sha256(
		NULL, 
		0, 
		dh_shared,
		sizeof(dh_shared),
		CHIPVPN_SESSION_HASH_A,
		sizeof(CHIPVPN_SESSION_HASH_A) - 1,
		role ? peer->inbound.session_hash : peer->outbound.session_hash,
		sizeof(peer->inbound.session_hash)
	);

	hkdf_sha256(
		NULL, 
		0, 
		dh_shared,
		sizeof(dh_shared),
		CHIPVPN_SESSION_HASH_B,
		sizeof(CHIPVPN_SESSION_HASH_B) - 1,
		role ? peer->outbound.session_hash : peer->inbound.session_hash,
		sizeof(peer->outbound.session_hash)
	);

	peer->address = *addr;
	peer->timestamp = ntohll(packet->timestamp);
	peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;
	peer->half_auth = false;

	chipvpn_peer_set_state(peer, PEER_CONNECTED);

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->inbound.session, peer->outbound.session);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	return 0;
}

int chipvpn_peer_send_ping(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp) {
	peer->counter++;

	chipvpn_packet_ping_t packet = {
		.header.type = CHIPVPN_PACKET_PING,
		.session = htonl(peer->outbound.session),
		.counter = htonll(peer->counter)
	};

	/* sign packet */
	chipvpn_dh_sign(
		peer->outbound.session_hash,
		peer->dh_ss,
		NULL,
		NULL,
		(uint8_t*)&packet,
		sizeof(packet),
		packet.sign
	);

	if(peer->config.onping) {
		chipvpn_peer_run_command(peer, peer->config.onping);
	}

	return chipvpn_socket_write(udp->socket, &packet, sizeof(packet), &peer->address);
}

int chipvpn_peer_recv_ping(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_packet_ping_t *packet, chipvpn_address_t *addr) {
	/* sign packet */
    uint8_t sign[SHA256_HASH_SIZE];
    uint8_t computed_sign[SHA256_HASH_SIZE];
    memcpy(sign, packet->sign, sizeof(sign));
    memset(packet->sign, 0, sizeof(packet->sign));

	chipvpn_dh_sign(
		peer->inbound.session_hash,
		peer->dh_ss,
		NULL,
		NULL,
		(uint8_t*)packet,
		sizeof(chipvpn_packet_ping_t),
		computed_sign
	);

	if(chipvpn_secure_memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
		chipvpn_log_append("%p says: invalid ping sign\n", peer);
		return 0;
	}

	if(peer->address.ip != addr->ip || peer->address.port != addr->port) {
		chipvpn_log_append("%p says: invalid src ip or src port\n", peer);
		return 0;
	}

	if(!chipvpn_bitmap_validate(&peer->bitmap, ntohll(packet->counter))) {
		chipvpn_log_append("%p says: rejected replayed ping\n", peer);
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

void chipvpn_peer_reset_session(chipvpn_peer_t *peer) {
	peer->tx = 0llu;
	peer->rx = 0llu;
	peer->timeout = 0llu;
	peer->last_check = 0llu;
	peer->counter = 0llu;
	peer->half_auth = false;

	chipvpn_bitmap_reset(&peer->bitmap);

	chipvpn_secure_zero(&peer->inbound, sizeof(peer->inbound));
	chipvpn_secure_zero(&peer->outbound, sizeof(peer->outbound));

	chipvpn_secure_zero(peer->ephemeral_public, sizeof(peer->ephemeral_public));
	chipvpn_secure_zero(peer->ephemeral_private, sizeof(peer->ephemeral_private));
	
	chipvpn_secure_zero(peer->dh_ee, sizeof(peer->dh_ee));
	chipvpn_secure_zero(peer->dh_es, sizeof(peer->dh_es));
	chipvpn_secure_zero(peer->dh_se, sizeof(peer->dh_se));
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
		switch(state) {
			case PEER_CONNECTED: {
				if(peer->config.onconnect) {
					chipvpn_peer_run_command(peer, peer->config.onconnect);
				}
			}
			break;
			case PEER_DISCONNECTED: {
				if(peer->config.ondisconnect) {
					chipvpn_peer_reset_session(peer);
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

	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		if(now - peer->last_check > CHIPVPN_PEER_PING) {
			peer->last_check = now;

			if(peer->state == PEER_CONNECTED) {
				/* ping peers */
				chipvpn_peer_send_ping(peer, device, udp);
				
				if(now > peer->timeout) {
					chipvpn_log_append("%p says: peer disconnected\n", peer);
					chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
				}
			} else if(peer->state != PEER_CONNECTED && peer->config.address.ip > 0) {
				/* attempt to connect to peer */
				chipvpn_log_append("%p says: connecting to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->config.address), peer->config.address.port);
				chipvpn_peer_send_connect(peer, device, udp, &peer->config.address, true);
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
		peer->outbound.session_hash, 
		sizeof(peer->outbound.session_hash), 
		mac
	);
}

bool chipvpn_peer_decrypt_payload(chipvpn_peer_t *peer, uint8_t *data, int size, uint64_t counter, uint8_t *mac) {
	return chipvpn_crypto_chacha20_poly1305_decrypt(
		peer->inbound.key, 
		data, 
		size, 
		counter, 
		peer->inbound.session_hash, 
		sizeof(peer->inbound.session_hash), 
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