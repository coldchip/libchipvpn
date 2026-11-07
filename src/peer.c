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
#include "firewall.h"
#include "util.h"
#include "noise.h"
#include "queue.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	/* not scheduled until it is added to a device */
	chipvpn_timer_init(&peer->timer);

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

int chipvpn_peer_send_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *addr) {
	chipvpn_log_append("%p says: keying to [%s]:%i\n", peer, chipvpn_address_to_char(addr), addr->port);

	chipvpn_packet_auth_t packet;

	if(!chipvpn_noise_produce_connect(peer, device, &packet)) {
		chipvpn_log_append("noise handshake failed\n");
		return 0;
	}

	/* any outbound packet is considered sending a keepalive packet */
	peer->last_transmission = chipvpn_get_time();

	return chipvpn_queue_push(&udp->tx_queue, &packet, sizeof(packet), addr);
}

int chipvpn_peer_recv_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_packet_auth_t *packet, const chipvpn_address_t *addr) {
	/* authenticated */
	if(!chipvpn_peer_send_auth_reply(peer, device, udp, addr)) {
		chipvpn_log_append("noise handshake failed\n");
		return 0;
	}

	if(!chipvpn_noise_begin_session(peer, false)) {
		chipvpn_log_append("peer failed to create session\n");
		return 0;
	}

	peer->address = *addr;

	/* expects a keepalive packet from initiator */
	peer->ack_state = PEER_ACK_OWE_TX;
	peer->last_ack = chipvpn_get_time();

	/* report status on the next service */
	peer->last_status = 0llu;
	peer->last_handshake = chipvpn_get_time();

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->handshake.inbound_id, peer->handshake.outbound_id);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	/* wipe handshake data */
	chipvpn_peer_reset_handshake(peer);

	return 0;
}

int chipvpn_peer_send_auth_reply(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *addr) {
	chipvpn_log_append("%p says: replying auth to [%s:%i]\n", peer, chipvpn_address_to_char(addr), addr->port);

	chipvpn_packet_auth_reply_t packet;

	if(!chipvpn_noise_produce_reply(peer, device, &packet)) {
		chipvpn_log_append("noise handshake failed\n");
		return 0;
	}

	/* any outbound packet is considered sending a keepalive packet */
	peer->last_transmission = chipvpn_get_time();

	return chipvpn_queue_push(&udp->tx_queue, &packet, sizeof(packet), addr);
}

int chipvpn_peer_recv_auth_reply(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_packet_auth_reply_t *packet, const chipvpn_address_t *addr) {
	/* authenticated */
	if(!chipvpn_noise_begin_session(peer, true)) {
		chipvpn_log_append("peer failed to create session\n");
		return 0;
	}

	peer->address = *addr;

	/* responder expects a keepalive packet (immediately) */
	peer->ack_state = PEER_ACK_OWE_RX;
	peer->last_ack = 0llu;

	/* report status on the next service */
	peer->last_status = 0llu;
	peer->last_handshake = chipvpn_get_time();

	/* promote peer session immediately from next_session to session */
	chipvpn_peer_session_promote(peer);

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->handshake.inbound_id, peer->handshake.outbound_id);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	/* wipe handshake data */
	chipvpn_peer_reset_handshake(peer);

	return 0;
}

int chipvpn_peer_send_keepalive(chipvpn_peer_t *peer, chipvpn_udp_t *udp) {
	chipvpn_log_append("%p says: sent keepalive packet\n", peer);

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
		chipvpn_log_append("%p says: unable to encrypt payload\n", peer);
		return 0;
	}

	if(peer->ack_state != PEER_ACK_OWE_TX) {
		peer->ack_state = PEER_ACK_IDLE;
	}

	/* any outbound packet is considered sending a keepalive packet */
	peer->last_transmission = chipvpn_get_time();

	chipvpn_queue_vector_t vector[] = {
		{ .data = &header, .size = sizeof(header) }, 
		{ .data = mac, .size = sizeof(mac) }
	};

	return chipvpn_queue_push_vector(&udp->tx_queue, vector, 2, &peer->address);
}

int chipvpn_peer_recv_keepalive(chipvpn_peer_t *peer) {
	chipvpn_log_append("%p says: received keepalive packet\n", peer);

	if(peer->ack_state != PEER_ACK_OWE_RX) {
		peer->ack_state = PEER_ACK_IDLE;
	}

	return 0;
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
	chipvpn_log_append("%p says: clearing handshake data\n", peer);

	chipvpn_secure_zero(&peer->handshake, sizeof(peer->handshake));
}

void chipvpn_peer_reset_session(chipvpn_peer_t *peer) {
	chipvpn_log_append("%p says: clearing session data\n", peer);

	peer->tx = 0llu;
	peer->rx = 0llu;
	peer->last_ack = 0;
	peer->ack_state = PEER_ACK_IDLE;

	chipvpn_secure_zero(&peer->prev_session, sizeof(peer->prev_session));
	chipvpn_secure_zero(&peer->session, sizeof(peer->session));
	chipvpn_secure_zero(&peer->next_session, sizeof(peer->next_session));
}

bool chipvpn_peer_add_allowip(chipvpn_peer_t *peer, const char *address, uint8_t prefix) {
	size_t i = peer->config.allow_size;

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
	return b64_decode((const uint8_t*)key, strlen(key), peer->config.public) == CURVE25519_KEY_SIZE;
}

bool chipvpn_peer_set_psk(chipvpn_peer_t *peer, const char *key) {
	return b64_decode((const uint8_t*)key, strlen(key), peer->config.psk) == BLAKE2S_HASH_SIZE;
}

void chipvpn_peer_session_promote(chipvpn_peer_t *peer) {
	chipvpn_log_append("%p says: promote session\n", peer);

	memcpy(&peer->prev_session, &peer->session, sizeof(peer->session));
	memset(&peer->session, 0, sizeof(peer->session));
	memcpy(&peer->session, &peer->next_session, sizeof(peer->next_session));
	memset(&peer->next_session, 0, sizeof(peer->next_session));
}

/* timed events of a peer, in the order chipvpn_peer_service handles them */
typedef enum {
	PEER_EVENT_STATUS,     /* log the peer status while it is active */
	PEER_EVENT_RESET,      /* clear the session once the peer is no longer active */
	PEER_EVENT_REKEY,      /* send a handshake initiation */
	PEER_EVENT_KEEPALIVE,  /* send a keepalive */
	PEER_EVENT_EXPIRE,     /* remove an inactive ephemeral peer */
	PEER_EVENT_COUNT
} chipvpn_peer_event_e;

static bool chipvpn_peer_has_session(const chipvpn_peer_t *peer) {
	return (
		peer->prev_session.inbound.id != 0 ||
		peer->prev_session.outbound.id != 0 ||
		peer->session.inbound.id != 0 ||
		peer->session.outbound.id != 0 ||
		peer->next_session.inbound.id != 0 ||
		peer->next_session.outbound.id != 0
	);
}

/* one timer rule: `event` is due `interval` ms after `since`, but not before `not_before`, while `armed` is true */
/* an event with several rules is due at the earliest of them */
static void chipvpn_peer_rule(uint64_t *deadline, chipvpn_peer_event_e event, bool armed, uint64_t since, uint64_t interval, uint64_t not_before) {
	if(armed) {
		uint64_t due = MAX(since + interval, not_before);
		deadline[event] = MIN(deadline[event], due);
	}
}

/* the peer timer rules, the only place they are defined */
/* fills deadline[] with the time each event is due (in the past if it is due now), CHIPVPN_TIMER_NEVER if it isn't pending */
/* `armed` may only switch on through a state change that calls chipvpn_device_update_peer_timer (handshake, data, config). */
/* it may switch off as time passes (the fresh and active windows close), which only leaves a wakeup that does nothing. */
/* a condition that switches on as time passes goes in `not_before` instead */
static void chipvpn_peer_deadlines(const chipvpn_peer_t *peer, uint64_t now, uint64_t *deadline) {
	bool active      = chipvpn_peer_is_active(peer, now);
	bool fresh       = chipvpn_peer_is_fresh(peer, now);
	bool has_session = chipvpn_peer_has_session(peer);
	bool initiator   = chipvpn_peer_is_initiator(peer);
	bool ephemeral   = peer->type == PEER_EPHEMERAL;
	bool owe_tx      = peer->ack_state == PEER_ACK_OWE_TX;  /* we sent data and wait for a reply */
	bool owe_rx      = peer->ack_state == PEER_ACK_OWE_RX;  /* we received data and owe a reply */

	/* handshake retries are paced, and an ephemeral peer only expires once its session has */
	uint64_t next_retry  = peer->last_initiation + CHIPVPN_REKEY_RETRY;
	uint64_t session_end = peer->last_handshake + CHIPVPN_REJECT_AFTER_TIME;

	for(int event = 0; event < PEER_EVENT_COUNT; event++) {
		deadline[event] = CHIPVPN_TIMER_NEVER;
	}

	/*                          event                 armed while      since                    interval                                           not before */
	chipvpn_peer_rule(deadline, PEER_EVENT_STATUS,    active,          peer->last_status,       CHIPVPN_STATUS_INTERVAL,                           0);
	chipvpn_peer_rule(deadline, PEER_EVENT_RESET,     has_session,     peer->last_handshake,    CHIPVPN_REJECT_AFTER_TIME,                         0);
	chipvpn_peer_rule(deadline, PEER_EVENT_REKEY,     initiator,       peer->last_handshake,    CHIPVPN_REKEY_AFTER_TIME,                          next_retry);
	chipvpn_peer_rule(deadline, PEER_EVENT_REKEY,     fresh && owe_tx, peer->last_ack,          CHIPVPN_KEEPALIVE_TIMEOUT + CHIPVPN_REKEY_TIMEOUT, next_retry);
	chipvpn_peer_rule(deadline, PEER_EVENT_KEEPALIVE, fresh,           peer->last_transmission, CHIPVPN_PERSISTENT_KEEPALIVE,                      0);
	chipvpn_peer_rule(deadline, PEER_EVENT_KEEPALIVE, fresh && owe_rx, peer->last_ack,          CHIPVPN_KEEPALIVE_TIMEOUT,                         0);
	chipvpn_peer_rule(deadline, PEER_EVENT_EXPIRE,    ephemeral,       peer->last_created,      CHIPVPN_EPHEMERAL_EXPIRY,                          session_end);
}

static bool chipvpn_peer_event_due(const chipvpn_peer_t *peer, chipvpn_peer_event_e event, uint64_t now) {
	uint64_t deadline[PEER_EVENT_COUNT];
	chipvpn_peer_deadlines(peer, now, deadline);

	return now >= deadline[event];
}

bool chipvpn_peer_service(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, uint64_t now) {
	/* peer lifecycle service, runs when the peer's timer fires and handles every event that is due */
	/* each check reads the rules again, an earlier event can change a later one (a handshake counts as a keepalive) */

	/* periodic status report */
	if(chipvpn_peer_event_due(peer, PEER_EVENT_STATUS, now)) {
		peer->last_status = now;

		char tx[128];
		char rx[128];
		strcpy(tx, chipvpn_format_bytes(peer->tx));
		strcpy(rx, chipvpn_format_bytes(peer->rx));

		chipvpn_log_append("%p says: peer alive, last handshake: [%lu] second(s)\n", peer, (now - peer->last_handshake) / 1000);
		chipvpn_log_append("%p says: tx: [%s] rx: [%s]\n", peer, tx, rx);
	}

	/* clear peer's session while in disconnected state */
	if(chipvpn_peer_event_due(peer, PEER_EVENT_RESET, now)) {
		chipvpn_peer_reset_session(peer);
	}

	/* whenever peer requires a rekey */
	if(chipvpn_peer_event_due(peer, PEER_EVENT_REKEY, now)) {
		peer->last_initiation = now;

		chipvpn_peer_send_connect(
			peer, 
			device, 
			udp, 
			chipvpn_peer_is_initiator(peer) ? &peer->config.endpoint : &peer->address
		);
	}

	/* whenever peer requires a keepalive */
	if(chipvpn_peer_event_due(peer, PEER_EVENT_KEEPALIVE, now)) {
		chipvpn_peer_send_keepalive(peer, udp);
	}

	/* remove peer if it is ephemeral and has timeout */
	if(chipvpn_peer_event_due(peer, PEER_EVENT_EXPIRE, now)) {
		chipvpn_log_append("%p says: ephemeral peer has expired\n", peer);
		return false;
	}

	return true;
}

uint64_t chipvpn_peer_next_deadline(const chipvpn_peer_t *peer, uint64_t now) {
	/* the earliest deadline among the peer's events, in the past if one is due already */
	uint64_t deadline[PEER_EVENT_COUNT];
	chipvpn_peer_deadlines(peer, now, deadline);

	uint64_t next = CHIPVPN_TIMER_NEVER;

	for(int event = 0; event < PEER_EVENT_COUNT; event++) {
		next = MIN(next, deadline[event]);
	}

	return next;
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	chipvpn_peer_reset_handshake(peer);
	chipvpn_peer_reset_session(peer);

	chipvpn_firewall_cleanup(&peer->firewall_inbound);
	chipvpn_firewall_cleanup(&peer->firewall_outbound);

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	free(peer);
}