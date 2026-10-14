#ifndef PEER_H
#define PEER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>
#include "chacha20poly1305.h"
#include "socket.h"
#include "address.h"
#include "bitmap.h"
#include "list.h"
#include "device.h"
#include "packet.h"
#include "chipvpn.h"
#include "curve25519.h"
#include "blake2s.h"
#include "util.h"

/* timers (wireguard compliant) */
#define CHIPVPN_REKEY_AFTER_TIME 120000
#define CHIPVPN_REJECT_AFTER_TIME 180000
#define CHIPVPN_KEEPALIVE_TIMEOUT 10000
#define CHIPVPN_REKEY_TIMEOUT 5000

typedef enum {
	PEER_ACK_IDLE,
	PEER_ACK_OWE_TX,
	PEER_ACK_OWE_RX
} chipvpn_peer_ack_e;

typedef enum {
	PEER_PERMANENT,
	PEER_EPHEMERAL
} chipvpn_peer_type_e;

#define PEER_IS_INITIATOR(peer)    (peer->config.address.ip > 0)
#define PEER_IS_EXPIRE(peer, now)  (peer->type == PEER_EPHEMERAL && GTEQ(now, peer->expiry))

#define PEER_NEXT_REKEY(peer)      (peer->last_handshake + CHIPVPN_REKEY_AFTER_TIME)
#define PEER_NEXT_DISCONNECT(peer) (peer->last_handshake + CHIPVPN_REJECT_AFTER_TIME)

#define PEER_CONNECTED(peer, now)  (GTEQ(now, peer->last_handshake) && LT(now, PEER_NEXT_DISCONNECT(peer)))
#define PEER_FRESH(peer, now)      (GTEQ(now, peer->last_handshake) && LT(now, PEER_NEXT_REKEY(peer)))

#define PEER_OVERDUE_TX(peer, now)   ( \
	GTEQ(now, peer->next_ack) && \
	peer->ack_state == PEER_ACK_OWE_TX \
)

#define PEER_OVERDUE_RX(peer, now)   ( \
	GTEQ(now, peer->next_ack) && \
	peer->ack_state == PEER_ACK_OWE_RX \
)

#define PEER_NEED_REKEY(peer, now) ( \
	( \
		/* premise 1: if peer is disconnected and an is an initiator */ \
		!PEER_CONNECTED(peer, now) && \
		PEER_IS_INITIATOR(peer) \
	) || \
	( \
		/* premise 2: if peer's session is stale */ \
		PEER_CONNECTED(peer, now) && \
		!PEER_FRESH(peer, now) \
	) || \
	( \
		/* premise 3: if peer TX is not acknowledged while its fresh */ \
		PEER_FRESH(peer, now) && \
		PEER_OVERDUE_TX(peer, now) \
	) \
)

#define PEER_NEED_KEEPALIVE(peer, now)  ( \
	( \
		/* premise 1: if peer RX is not acknowledged while its fresh */ \
		PEER_FRESH(peer, now) && \
		PEER_OVERDUE_RX(peer, now) \
	) \
)

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
		chipvpn_address_t address;
		chipvpn_address_t allow;
		uint8_t public[CURVE25519_KEY_SIZE];
		uint8_t psk[BLAKE2S_HASH_SIZE];
	} config;

	/* states and timers */
	chipvpn_peer_type_e type;
	uint8_t timestamp[TAI64N_SIZE];
	uint64_t tx;
	uint64_t rx;
	uint64_t last_check;
	uint64_t last_handshake;
	uint64_t next_ack;
	uint64_t expiry;
	chipvpn_peer_ack_e ack_state;
} chipvpn_peer_t;

chipvpn_peer_t         *chipvpn_peer_create();

int                     chipvpn_peer_send_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr);
int                     chipvpn_peer_recv_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *socket, chipvpn_packet_auth_t *packet, chipvpn_address_t *addr);
int                     chipvpn_peer_send_auth_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr);
int                     chipvpn_peer_recv_auth_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_packet_auth_reply_t *packet, chipvpn_address_t *addr);

int                     chipvpn_peer_send_keepalive(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *socket);
int                     chipvpn_peer_recv_keepalive(chipvpn_peer_t *peer);

void                    chipvpn_peer_reset_handshake(chipvpn_peer_t *peer);
void                    chipvpn_peer_reset_session(chipvpn_peer_t *peer);

bool                    chipvpn_peer_set_allow(chipvpn_peer_t *peer, const char *address, uint8_t prefix);
bool                    chipvpn_peer_set_address(chipvpn_peer_t *peer, const char *address, uint16_t port);
bool                    chipvpn_peer_set_public_key(chipvpn_peer_t *peer, chipvpn_device_t *device, const char *key);
bool                    chipvpn_peer_set_psk(chipvpn_peer_t *peer, const char *key);
void                    chipvpn_peer_session_promote(chipvpn_peer_t *peer);
void                    chipvpn_peer_service(chipvpn_list_t *peers, chipvpn_device_t *device, chipvpn_udp_t *socket);

void                    chipvpn_peer_free(chipvpn_peer_t *peer);

#ifdef __cplusplus
}
#endif

#endif