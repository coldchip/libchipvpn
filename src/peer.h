#ifndef PEER_H
#define PEER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>
#include "chacha20poly1305.h"
#include "address.h"
#include "bitmap.h"
#include "list.h"
#include "device.h"
#include "packet.h"
#include "chipvpn.h"
#include "curve25519.h"
#include "blake2s.h"
#include "util.h"
#include "timer.h"

/* timers (wireguard compliant) */
#define CHIPVPN_REKEY_AFTER_TIME 120000
#define CHIPVPN_REJECT_AFTER_TIME 180000
#define CHIPVPN_KEEPALIVE_TIMEOUT 10000
#define CHIPVPN_REKEY_TIMEOUT 5000
#define CHIPVPN_PERSISTENT_KEEPALIVE 20000
#define CHIPVPN_EPHEMERAL_EXPIRY 60000

/* pacing of work that repeats while it is needed: handshake retries and status reports.
   both used to be paced by the fixed 2s peer polling loop and keep its interval */
#define CHIPVPN_REKEY_RETRY 2000
#define CHIPVPN_STATUS_INTERVAL 2000

/* when each status report, keepalive, rekey, session reset and expiry happens: see chipvpn_peer_deadlines() in peer.c */

typedef enum {
	PEER_ACK_IDLE,
	PEER_ACK_OWE_TX,
	PEER_ACK_OWE_RX
} chipvpn_peer_ack_e;

typedef enum {
	PEER_PERMANENT,
	PEER_EPHEMERAL
} chipvpn_peer_type_e;

typedef struct chipvpn_peer_session {
	chipvpn_list_node_t node;
	
	struct inbound {
		uint32_t id;
		uint8_t key[CHACHA20_KEY_SIZE];
	} inbound;

	struct outbound {
		uint32_t id;
		uint8_t key[CHACHA20_KEY_SIZE];
	} outbound;

	uint64_t counter;
	chipvpn_bitmap_t bitmap;
} chipvpn_peer_session_t;

typedef struct chipvpn_peer {
	chipvpn_list_node_t node;

	/* handshake and ephemerals */
	struct {
		uint32_t outbound_id;
		uint32_t inbound_id;

		uint8_t ephemeral_public[CURVE25519_KEY_SIZE];
		uint8_t ephemeral_private[CURVE25519_KEY_SIZE];

		uint8_t chain_key[BLAKE2S_HASH_SIZE];
		uint8_t hash_key[BLAKE2S_HASH_SIZE];
	} handshake;

	/* sessions */
	chipvpn_peer_session_t prev_session;
	chipvpn_peer_session_t session;
	chipvpn_peer_session_t next_session;

	chipvpn_address_t address;

	/* config */
	struct {
		chipvpn_address_t endpoint;
		chipvpn_address_t allow[128];
		size_t allow_size;
		uint8_t public[CURVE25519_KEY_SIZE];
		uint8_t psk[BLAKE2S_HASH_SIZE];
	} config;

	/* firewall */
	chipvpn_list_t firewall_inbound;
	chipvpn_list_t firewall_outbound;

	/* states and timers */
	/* fires when the peer next needs servicing, see chipvpn_peer_next_deadline() */
	chipvpn_timer_t timer;
	/* peer type, permanent or ephemeral */
	chipvpn_peer_type_e type;
	/* packets sent in the inner tunnel */
	uint64_t tx;
	/* packets received in the inner tunnel */
	uint64_t rx;
	/* last timestamp of the initiator */
	uint8_t timestamp[TAI64N_SIZE];
	/* last created, used for removing expired ephemeral peers */
	uint64_t last_created;
	/* last status report, repeated every CHIPVPN_STATUS_INTERVAL while the peer is active */
	uint64_t last_status;
	/* last handshake initiation sent, retries are paced by CHIPVPN_REKEY_RETRY */
	uint64_t last_initiation;
	/* last successful handshake with peer */
	uint64_t last_handshake;
	/* last packet sent, used for NAT traversal & persistent keepalive, updated when there is any tx packet */
	uint64_t last_transmission;
	/* last timestamp of the first unacknowledged tx or unreplied rx packet */
	uint64_t last_ack;
	/* keepalive timeout state that dictates the next timeout action */
	chipvpn_peer_ack_e ack_state;
} chipvpn_peer_t;

/* the session is fresh until CHIPVPN_REKEY_AFTER_TIME after the handshake, then it is time to rekey */
static inline bool chipvpn_peer_is_fresh(const chipvpn_peer_t *peer, uint64_t now) {
	return now >= peer->last_handshake && now < peer->last_handshake + CHIPVPN_REKEY_AFTER_TIME;
}

/* the session carries traffic until CHIPVPN_REJECT_AFTER_TIME after the handshake */
static inline bool chipvpn_peer_is_active(const chipvpn_peer_t *peer, uint64_t now) {
	return now >= peer->last_handshake && now < peer->last_handshake + CHIPVPN_REJECT_AFTER_TIME;
}

/* a peer with an endpoint starts the handshakes, the other side answers them */
static inline bool chipvpn_peer_is_initiator(const chipvpn_peer_t *peer) {
	return peer->config.endpoint.port > 0;
}

chipvpn_peer_t         *chipvpn_peer_create();

int                     chipvpn_peer_send_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *addr);
int                     chipvpn_peer_recv_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *socket, const chipvpn_packet_auth_t *packet, const chipvpn_address_t *addr);
int                     chipvpn_peer_send_auth_reply(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *addr);
int                     chipvpn_peer_recv_auth_reply(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_packet_auth_reply_t *packet, const chipvpn_address_t *addr);

int                     chipvpn_peer_send_keepalive(chipvpn_peer_t *peer, chipvpn_udp_t *socket);
int                     chipvpn_peer_recv_keepalive(chipvpn_peer_t *peer);

bool                    chipvpn_peer_allowip_match(const chipvpn_peer_t *peer, const chipvpn_address_t *address);

void                    chipvpn_peer_reset_handshake(chipvpn_peer_t *peer);
void                    chipvpn_peer_reset_session(chipvpn_peer_t *peer);

bool                    chipvpn_peer_add_allowip(chipvpn_peer_t *peer, const char *address, uint8_t prefix);
bool                    chipvpn_peer_set_endpoint(chipvpn_peer_t *peer, const char *address, uint16_t port);
bool                    chipvpn_peer_set_public_key(chipvpn_peer_t *peer, chipvpn_device_t *device, const char *key);
bool                    chipvpn_peer_set_psk(chipvpn_peer_t *peer, const char *key);
void                    chipvpn_peer_session_promote(chipvpn_peer_t *peer);

bool                    chipvpn_peer_service(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *socket, uint64_t now);
uint64_t                chipvpn_peer_next_deadline(const chipvpn_peer_t *peer, uint64_t now);

void                    chipvpn_peer_free(chipvpn_peer_t *peer);

#ifdef __cplusplus
}
#endif

#endif