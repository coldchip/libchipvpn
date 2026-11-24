#include "peer.h"
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h> 
#include <stdio.h>
#include <endian.h>
#include "chipvpn.h"
#include "packet.h"
#include "device.h"
#include "util.h"
#include "log.h"
#include "base64.h"
#include "firewall.h"
#include "noise.h"
#include "queue.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	peer->type = PEER_PERMANENT;

	if(!chipvpn_firewall_init(&peer->firewall_inbound)) {
		chipvpn_peer_free(peer);
		return NULL;
	}

	if(!chipvpn_firewall_init(&peer->firewall_outbound)) {
		chipvpn_peer_free(peer);
		return NULL;
	}

	return peer;
}

bool chipvpn_peer_send_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *address) {
	if(!chipvpn_queue_push_acquire(&udp->tx_queue)) {
		return false;
	}

	chipvpn_packet_auth_t packet;
	if(!chipvpn_noise_produce_connect(peer, device, &packet)) {
		return false;
	}

	/* update timers and clear pending passive keepalive */
	peer->last_transmission = chipvpn_get_tick();
	peer->last_initiation   = chipvpn_get_tick();
	PEER_ACK_CLEAR(peer, PEER_ACK_OWE_RX);

	LOG_INFO("%p says: keying to [%s]:%u\n", peer, chipvpn_address_to_char(address), address->port);

	return chipvpn_queue_push(&udp->tx_queue, &packet, sizeof(packet), address) > 0;
}

bool chipvpn_peer_recv_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *address) {
	/* authenticated */
	if(!chipvpn_peer_send_auth_reply(peer, device, udp, address)) {
		return false;
	}

	/* derive session and update peer state */
	chipvpn_noise_begin_session(peer, false);
	peer->address = *address;
	PEER_ACK_CLEAR(peer, PEER_ACK_OWE_TX);

	LOG_INFO("%p says: hello\n", peer);
	LOG_INFO("%p says: session: in [%u] out [%u]\n", peer, peer->handshake.inbound_id, peer->handshake.outbound_id);
	LOG_INFO("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	/* wipe handshake data */
	chipvpn_peer_reset_handshake(peer);

	return true;
}

bool chipvpn_peer_send_auth_reply(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *address) {
	if(!chipvpn_queue_push_acquire(&udp->tx_queue)) {
		return false;
	}

	chipvpn_packet_auth_reply_t packet;
	if(!chipvpn_noise_produce_reply(peer, device, &packet)) {
		return false;
	}

	/* update timers and clear pending passive keepalive */
	peer->last_transmission = chipvpn_get_tick();
	PEER_ACK_CLEAR(peer, PEER_ACK_OWE_RX);

	LOG_INFO("%p says: replying auth to [%s:%u]\n", peer, chipvpn_address_to_char(address), address->port);

	return chipvpn_queue_push(&udp->tx_queue, &packet, sizeof(packet), address) > 0;
}

bool chipvpn_peer_recv_auth_reply(chipvpn_peer_t *peer, chipvpn_udp_t *udp, const chipvpn_address_t *address) {
	/* authenticated */
	/* derive session and update peer state */
	chipvpn_noise_begin_session(peer, true);
	peer->address = *address;
	PEER_ACK_CLEAR(peer, PEER_ACK_OWE_TX);

	/* promote session immediately and send confirming keepalive */
	chipvpn_peer_session_promote(peer);
	chipvpn_peer_send_keepalive(peer, udp);

	LOG_INFO("%p says: hello\n", peer);
	LOG_INFO("%p says: session: in [%u] out [%u]\n", peer, peer->handshake.inbound_id, peer->handshake.outbound_id);
	LOG_INFO("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	/* wipe handshake data */
	chipvpn_peer_reset_handshake(peer);

	return true;
}

bool chipvpn_peer_send_keepalive(chipvpn_peer_t *peer, chipvpn_udp_t *udp) {
	if(!chipvpn_queue_push_acquire(&udp->tx_queue) || !SESSION_ACTIVE(&peer->session)) {
		return false;
	}

	peer->session.counter++;

	chipvpn_packet_data_t header = {
		.type    = CHIPVPN_PACKET_DATA,
		.session = htole32(peer->session.outbound.id),
		.counter = htole64(peer->session.counter)
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
		return false;
	}

	/* disarm PEER_ACK_OWE_RX because we sent a keepalive */
	PEER_ACK_CLEAR(peer, PEER_ACK_OWE_RX);

	/* any outbound packet is considered sending a keepalive packet */
	peer->last_transmission = chipvpn_get_tick();

	chipvpn_queue_vector_t vector[] = {
		{ .data = &header, .size = sizeof(header) }, 
		{ .data = mac, .size = sizeof(mac) }
	};

	return chipvpn_queue_push_vector(&udp->tx_queue, vector, 2, &peer->address) > 0;
}

void chipvpn_peer_recv_keepalive(chipvpn_peer_t *peer) {
	/* disarm PEER_ACK_OWE_TX because we received a keepalive */
	PEER_ACK_CLEAR(peer, PEER_ACK_OWE_TX);
}

bool chipvpn_peer_allowip_match(const chipvpn_peer_t *peer, const chipvpn_address_t *address) {
	for(size_t i = 0; i < peer->config.allow_size; i++) {
		if(chipvpn_address_network_match(&peer->config.allow[i], address)) {
			return true;
		}
	}

	return false;
}

void chipvpn_peer_reset_handshake(chipvpn_peer_t *peer) {
	LOG_INFO("%p says: clearing handshake data\n", peer);

	chipvpn_secure_zero(&peer->handshake, sizeof(peer->handshake));
}

void chipvpn_peer_reset_expired_session(chipvpn_peer_t *peer) {
	if(peer->prev_session.last_created != 0ULL && !SESSION_ACTIVE(&peer->prev_session)) {
		LOG_INFO("%p says: clearing expired prev session\n", peer);
		chipvpn_secure_zero(&peer->prev_session, sizeof(peer->prev_session));
	}

	if(peer->session.last_created != 0ULL && !SESSION_ACTIVE(&peer->session)) {
		LOG_INFO("%p says: clearing expired session\n", peer);
		chipvpn_secure_zero(&peer->session, sizeof(peer->session));
	}

	if(peer->next_session.last_created != 0ULL && !SESSION_ACTIVE(&peer->next_session)) {
		LOG_INFO("%p says: clearing expired next session\n", peer);
		chipvpn_secure_zero(&peer->next_session, sizeof(peer->next_session));
	}
}

bool chipvpn_peer_add_allowip(chipvpn_peer_t *peer, const char *address, uint8_t prefix) {
	size_t i = peer->config.allow_size;

	if(i >= PEER_MAX_ALLOWEDIPS) {
		return false;
	}

	if(!chipvpn_address_set_ip(&peer->config.allow[i], address)) {
		return false;
	}

	if(
		(peer->config.allow[i].type == CHIPVPN_ADDRESS_IPV6 && prefix > 128) ||
		(peer->config.allow[i].type == CHIPVPN_ADDRESS_IPV4 && prefix > 32)
	) {
		return false;
	}

	peer->config.allow[i].prefix = prefix;

	peer->config.allow_size++;

	return true;
}

bool chipvpn_peer_set_endpoint(chipvpn_peer_t *peer, const char *address, uint16_t port) {
	if(!chipvpn_address_set_ip(&peer->config.endpoint, address)) {
		return false;
	}

	peer->config.endpoint.port = port;
	return true;
}

bool chipvpn_peer_set_public_key(chipvpn_peer_t *peer, chipvpn_device_t *device, const char *key) {
	if(strlen(key) != 44) {
		return false;
	}

	return b64_decode((const uint8_t*)key, strlen(key), peer->config.static_public) == CURVE25519_KEY_SIZE;
}

bool chipvpn_peer_set_psk(chipvpn_peer_t *peer, const char *key) {
	if(strlen(key) != 44) {
		return false;
	}

	return b64_decode((const uint8_t*)key, strlen(key), peer->config.psk) == BLAKE2S_HASH_SIZE;
}

void chipvpn_peer_session_promote(chipvpn_peer_t *peer) {
	if(!SESSION_ACTIVE(&peer->next_session)) {
		return;
	}

	peer->prev_session = peer->session;
	peer->session      = peer->next_session;

	chipvpn_secure_zero(&peer->next_session, sizeof(peer->next_session));
}

bool chipvpn_peer_service(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp) {
	/* peer lifecycle service */
	chipvpn_peer_reset_expired_session(peer);

	if(SESSION_ACTIVE(&peer->session)) {
		char tx[128];
		char rx[128];
		strcpy(tx, chipvpn_format_bytes(peer->tx));
		strcpy(rx, chipvpn_format_bytes(peer->rx));

		LOG_INFO("%p says: peer alive, session age: [%" PRIu64 "] second(s)\n", peer, (chipvpn_get_tick() - peer->session.last_created) / 1000);
		LOG_INFO("%p says: tx: [%s] rx: [%s]\n", peer, tx, rx);
	}

	/* whenever peer requires a rekey */
	if(PEER_REKEY(peer)) {
		chipvpn_peer_send_connect(
			peer, 
			device, 
			udp, 
			PEER_INITIATOR(peer) ? &peer->config.endpoint : &peer->address
		);
	}

	/* whenever peer requires a keepalive */
	if(PEER_KEEPALIVE(peer)) {
		chipvpn_peer_send_keepalive(peer, udp);
	}

	/* remove peer if it is ephemeral and has timeout */
	if(PEER_EXPIRE(peer)) {
		LOG_INFO("%p says: ephemeral peer has expired\n", peer);
		return false;
	}

	return true;
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	chipvpn_firewall_cleanup(&peer->firewall_inbound);
	chipvpn_firewall_cleanup(&peer->firewall_outbound);

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	free(peer);
}