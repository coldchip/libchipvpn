#include "peer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "packet.h"
#include "util.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "hkdf_sha256.h"
#include "curve25519.h"
#include "crc32.h"
#include "log.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	/* use setter to set? */
	peer->state = PEER_DISCONNECTED;
	peer->inbound_session = 0;
	peer->outbound_session = 0;
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

int chipvpn_peer_send_connect(chipvpn_t *vpn, chipvpn_peer_t *peer, chipvpn_address_t *addr) {
	chipvpn_packet_auth_t packet = {
		.header.type = CHIPVPN_PACKET_AUTH,
		.version = htonl(CHIPVPN_PROTOCOL_VERSION),
		.timestamp = htonll(chipvpn_get_time())
	};

	// Generate curve25519 keys
	chipvpn_secure_random(peer->curve_private, sizeof(peer->curve_private));
	uint8_t curve_basepoint[32] = {9};
	curve25519(
		peer->curve_public, 
		peer->curve_private, 
		curve_basepoint
	);

	// Copy curve25519 public key to packet
	memcpy(packet.curve_public, peer->curve_public, sizeof(peer->curve_public));

	/* generate keyhash */
	chipvpn_peer_get_keyhash(peer, packet.keyhash);

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
	if(ntohl(packet->version) != CHIPVPN_PROTOCOL_VERSION) {
		chipvpn_log_append("invalid protocol version\n");
		return 0;
	}

	uint8_t sign[32];
	uint8_t computed_sign[32];
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

	// Auth successful
	if(!peer->config.connect) {
		chipvpn_log_append("%p says: peer requested auth acknowledgement\n", peer);
		chipvpn_peer_send_connect(vpn, peer, addr);
	}

	// Reject if peer has same curve25519 public key
	if(chipvpn_secure_memcmp(packet->curve_public, peer->curve_public, sizeof(packet->curve_public)) == 0) {
		chipvpn_log_append("peer has the same curve25519 keys\n");
		return 0;
	}

	// Derive curve25519 shared keys
	uint8_t curve_shared[CURVE25519_KEY_SIZE];
	curve25519(
		curve_shared, 
		peer->curve_private, 
		packet->curve_public
	);

	// Securely derive chacha20 keys by hmac256 with shared curve25519 keys
	int role = memcmp(peer->curve_public, packet->curve_public, sizeof(peer->curve_public)) > 0;

	hkdf_sha256(
		NULL, 
		0, 
		curve_shared,
		sizeof(curve_shared),
		"#CHIPVPN_DIRECTIONAL_KEY_A/1.0",
		18,
		role ? peer->inbound_key : peer->outbound_key,
		sizeof(peer->inbound_key)
	);

	hkdf_sha256(
		NULL, 
		0, 
		curve_shared,
		sizeof(curve_shared),
		"#CHIPVPN_DIRECTIONAL_KEY_B/1.0",
		18,
		role ? peer->inbound_key : peer->outbound_key,
		sizeof(peer->inbound_key)
	);

	// Clear curve25519 keys
	memset(peer->curve_public, 0, sizeof(peer->curve_public));
	memset(peer->curve_private, 0, sizeof(peer->curve_private));

	// Derive session id from keys
	uint32_t inbound_session  = crc32(peer->inbound_key, sizeof(peer->inbound_key));
	uint32_t outbound_session = crc32(peer->outbound_key, sizeof(peer->outbound_key));

	if(inbound_session == outbound_session) {
		chipvpn_log_append("inbound session and outbound session collision\n");
		return 0;
	}

	// Set peer state
	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	peer->inbound_session  = inbound_session;
	peer->outbound_session = outbound_session;
	peer->address = *addr;
	peer->timestamp = ntohll(packet->timestamp);
	peer->tx = 0l;
	peer->rx = 0l;
	peer->counter = 0l;
	peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;
	chipvpn_bitmap_reset(&peer->bitmap);
	chipvpn_peer_set_state(peer, PEER_CONNECTED);

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->inbound_session, peer->outbound_session);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	return 0;
}

int chipvpn_peer_send_ping(chipvpn_t *vpn, chipvpn_peer_t *peer) {
	chipvpn_packet_ping_t packet = {
		.header.type = CHIPVPN_PACKET_PING,
		.session = htonl(peer->outbound_session),
		.counter = htonll(peer->counter)
	};

	// Derive session hash from key(so this packet cannot be replayed for other session)
	hkdf_sha256(
		NULL, 
		0, 
		peer->outbound_key, 
		sizeof(peer->outbound_key),
		"#CHIPVPN_SESSION_HASH/1.0",
		30,
		packet.session_hash, 
		sizeof(packet.session_hash)
	);

	/* sign packet */
	memset(packet.sign, 0, sizeof(packet.sign));
	hmac_sha256(
		peer->outbound_key, 
		sizeof(peer->outbound_key),
		&packet,
		sizeof(packet),
		packet.sign, 
		sizeof(packet.sign)
	);

	peer->counter++;

	if(peer->config.onping) {
		chipvpn_peer_run_command(peer, peer->config.onping);
	}

	return chipvpn_socket_write(vpn->socket, &packet, sizeof(packet), &peer->address);
}

int chipvpn_peer_recv_ping(chipvpn_peer_t *peer, chipvpn_packet_ping_t *packet, chipvpn_address_t *addr) {
	/* sign packet */
	uint8_t sign[32];
	uint8_t computed_sign[32];
	memcpy(sign, packet->sign, sizeof(sign));
	memset(packet->sign, 0, sizeof(packet->sign));
	hmac_sha256(
		peer->inbound_key, 
		sizeof(peer->inbound_key),
		packet,
		sizeof(chipvpn_packet_ping_t),
		computed_sign,
		sizeof(computed_sign)
	);

	if(chipvpn_secure_memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
		chipvpn_log_append("%p says: invalid ping sign\n", peer);
		return 0;
	}

	// Derive session hash from key(so this packet cannot be replayed for other session)
	uint8_t session_hash[32];
	hkdf_sha256(
		NULL, 
		0, 
		peer->inbound_key, 
		sizeof(peer->inbound_key),
		"#CHIPVPN_SESSION_HASH/1.0",
		30,
		session_hash, 
		sizeof(session_hash)
	);

	if(chipvpn_secure_memcmp(packet->session_hash, session_hash, sizeof(packet->session_hash)) != 0) {
		chipvpn_log_append("%p says: invalid session hash\n", peer);
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

void chipvpn_peer_get_keyhash(chipvpn_peer_t *peer, uint8_t *keyhash) {
	hmac_sha256(
		peer->config.key, 
		sizeof(peer->config.key),
		"#CHIPVPN_KEYHASH/1.0",
		20,
		keyhash, 
		32
	);
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
	sha256((uint8_t*)key, strlen(key), peer->config.key, sizeof(peer->config.key));

	return true;
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

chipvpn_peer_t *chipvpn_peer_get_by_keyhash(chipvpn_list_t *peers, uint8_t *key) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		uint8_t current[32];
		
		chipvpn_peer_get_keyhash(peer, current);

		if(chipvpn_secure_memcmp(key, current, sizeof(current)) == 0) {
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
		
		if(session == peer->inbound_session) {
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

		uint8_t keyhash_buffer[32];
		chipvpn_peer_get_keyhash(peer, keyhash_buffer);

		memset(keyhash, 0, sizeof(keyhash));
		for(int i = 0; i < 32; i++) {
			sprintf(&keyhash[i * 2], "%02x", keyhash_buffer[i] & 0xff);
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