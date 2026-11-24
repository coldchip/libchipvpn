#ifndef PEER_H
#define PEER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>
#include "chacha20.h"
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

/* timers (wireguard compliant) */
#define CHIPVPN_REKEY_AFTER_TIME     120000ULL
#define CHIPVPN_REJECT_AFTER_TIME    180000ULL
#define CHIPVPN_KEEPALIVE_TIMEOUT    10000ULL
#define CHIPVPN_REKEY_TIMEOUT        5000ULL
#define CHIPVPN_PERSISTENT_KEEPALIVE 20000ULL
#define CHIPVPN_EPHEMERAL_EXPIRY     60000ULL

/* session timer logic */
#define SESSION_NEXT_STALE(session)    ((session)->last_created + CHIPVPN_REKEY_AFTER_TIME)
#define SESSION_NEXT_INACTIVE(session) ((session)->last_created + CHIPVPN_REJECT_AFTER_TIME)

#define SESSION_ACTIVE(session) ( \
	GTEQ(chipvpn_get_tick(), (session)->last_created) && \
	LT(chipvpn_get_tick(), SESSION_NEXT_INACTIVE(session)) \
)

#define SESSION_FRESH(session) ( \
	GTEQ(chipvpn_get_tick(), (session)->last_created) && \
	LT(chipvpn_get_tick(), SESSION_NEXT_STALE(session)) \
)

/* peer timer logic */
#define PEER_NEXT_OVERDUE_TX(peer) ((peer)->last_ack + CHIPVPN_KEEPALIVE_TIMEOUT + CHIPVPN_REKEY_TIMEOUT)
#define PEER_NEXT_OVERDUE_RX(peer) ((peer)->last_ack + CHIPVPN_KEEPALIVE_TIMEOUT)
#define PEER_NEXT_RETRY(peer)      ((peer)->last_initiation + CHIPVPN_REKEY_TIMEOUT)
#define PEER_NEXT_KEEPALIVE(peer)  ((peer)->last_transmission + CHIPVPN_PERSISTENT_KEEPALIVE)
#define PEER_NEXT_EXPIRY(peer)     ((peer)->last_created + CHIPVPN_EPHEMERAL_EXPIRY)

/* base state predicates */
#define PEER_INITIATOR(peer) ((peer)->config.endpoint.port > 0U)

/* sub-trigger predicates */
#define PEER_OVERDUE_TX(peer) ( \
	SESSION_ACTIVE(&(peer)->session) && \
	(peer)->ack_state == PEER_ACK_OWE_TX && \
	GTEQ(chipvpn_get_tick(), PEER_NEXT_OVERDUE_TX(peer)) \
)

#define PEER_OVERDUE_RX(peer) ( \
	SESSION_ACTIVE(&(peer)->session) && \
	(peer)->ack_state == PEER_ACK_OWE_RX && \
	GTEQ(chipvpn_get_tick(), PEER_NEXT_OVERDUE_RX(peer)) \
)

#define PEER_PERIODIC_REKEY(peer) ( \
	!SESSION_FRESH(&(peer)->session) && \
	PEER_INITIATOR(peer) \
)

#define PEER_PERIODIC_KEEPALIVE(peer) ( \
	SESSION_ACTIVE(&(peer)->session) && \
	GTEQ(chipvpn_get_tick(), PEER_NEXT_KEEPALIVE(peer)) \
)

/* top-level predicates */
#define PEER_REKEY(peer) ( \
	GTEQ(chipvpn_get_tick(), PEER_NEXT_RETRY(peer)) && \
	( \
		PEER_PERIODIC_REKEY(peer) || \
		PEER_OVERDUE_TX(peer) \
	) \
)

#define PEER_KEEPALIVE(peer) ( \
	PEER_PERIODIC_KEEPALIVE(peer) || \
	PEER_OVERDUE_RX(peer) \
)

#define PEER_EXPIRE(peer) ( \
	!SESSION_ACTIVE(&(peer)->session) && \
	(peer)->type == PEER_EPHEMERAL && \
	GTEQ(chipvpn_get_tick(), PEER_NEXT_EXPIRY(peer)) \
)

/* ack state transitions */
#define PEER_ACK_CLEAR(peer, state) do { \
	if((peer)->ack_state == (state)) { \
		(peer)->ack_state = PEER_ACK_IDLE; \
		(peer)->last_ack  = 0ULL; \
	} \
} while(0)

#define PEER_ACK_ARM(peer, state) do { \
	if((peer)->ack_state != (state)) { \
		(peer)->ack_state = (state); \
		(peer)->last_ack  = chipvpn_get_tick(); \
	} \
} while(0)

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
	/* last timestamp when session was first derived */
	uint64_t last_created;
	
	/* inbound id and key */
	struct {
		uint32_t id;
		uint8_t key[CHACHA20_KEY_SIZE];
	} inbound;

	/* outbound id and key */
	struct {
		uint32_t id;
		uint8_t key[CHACHA20_KEY_SIZE];
	} outbound;

	uint64_t counter;
	chipvpn_bitmap_t bitmap;
} chipvpn_peer_session_t;

#define PEER_MAX_ALLOWEDIPS 128

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
		chipvpn_address_t allow[PEER_MAX_ALLOWEDIPS];
		size_t allow_size;
		uint8_t static_public[CURVE25519_KEY_SIZE];
		uint8_t psk[BLAKE2S_HASH_SIZE];
	} config;

	/* firewall */
	chipvpn_list_t firewall_inbound;
	chipvpn_list_t firewall_outbound;

	/* states and timers */
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
	/* last handshake initiation sent, retries are paced by CHIPVPN_REKEY_TIMEOUT */
	uint64_t last_initiation;
	/* last packet sent, used for NAT traversal & persistent keepalive, updated when there is any tx packet */
	uint64_t last_transmission;
	/* last timestamp of the first unacknowledged tx or unreplied rx packet */
	uint64_t last_ack;
	/* keepalive timeout state that dictates the next timeout action */
	chipvpn_peer_ack_e ack_state;
} chipvpn_peer_t;

chipvpn_peer_t         *chipvpn_peer_create();

bool                    chipvpn_peer_send_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *address);
bool                    chipvpn_peer_recv_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *address);
bool                    chipvpn_peer_send_auth_reply(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp, const chipvpn_address_t *address);
bool                    chipvpn_peer_recv_auth_reply(chipvpn_peer_t *peer, chipvpn_udp_t *udp, const chipvpn_address_t *address);

bool                    chipvpn_peer_send_keepalive(chipvpn_peer_t *peer, chipvpn_udp_t *socket);
void                    chipvpn_peer_recv_keepalive(chipvpn_peer_t *peer);

bool                    chipvpn_peer_allowip_match(const chipvpn_peer_t *peer, const chipvpn_address_t *address);

void                    chipvpn_peer_reset_handshake(chipvpn_peer_t *peer);
void                    chipvpn_peer_reset_expired_session(chipvpn_peer_t *peer);

bool                    chipvpn_peer_add_allowip(chipvpn_peer_t *peer, const char *address, uint8_t prefix);
bool                    chipvpn_peer_set_endpoint(chipvpn_peer_t *peer, const char *address, uint16_t port);
bool                    chipvpn_peer_set_public_key(chipvpn_peer_t *peer, chipvpn_device_t *device, const char *key);
bool                    chipvpn_peer_set_psk(chipvpn_peer_t *peer, const char *key);
void                    chipvpn_peer_session_promote(chipvpn_peer_t *peer);

bool                    chipvpn_peer_service(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_udp_t *udp);

void                    chipvpn_peer_free(chipvpn_peer_t *peer);

#ifdef __cplusplus
}
#endif

#endif