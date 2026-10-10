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
#include "firewall.h"
#include "curve25519.h"
#include "blake2s.h"
#include "util.h"

#define GT(test, a) (test > a)
#define LT(test, a) (test < a)
#define GTEQ(test, a) (test >= a)
#define LTEQ(test, a) (test <= a)
#define BETWEEN(test, a, b) (GTEQ(test, a) && LTEQ(test, b))

#define CHIPVPN_REKEY_AFTER_TIME 120000
#define CHIPVPN_REKEY_DURATION 60000
#define CHIPVPN_KEEPALIVE_TIMEOUT 10000
#define CHIPVPN_REKEY_TIMEOUT 5000


typedef enum {
	PEER_DISCONNECTED,
	PEER_CONNECTED
} chipvpn_peer_state_e;

typedef enum {
	PEER_ACK_IDLE,
	PEER_ACK_OWE_TX,
	PEER_ACK_OWE_RX
} chipvpn_peer_ack_e;

typedef enum {
	PEER_PERMANENT,
	PEER_EPHEMERAL
} chipvpn_peer_type_e;

typedef struct {
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

typedef struct chipvpn_peer_t {
	chipvpn_list_node_t node;
	chipvpn_peer_state_e state;
	chipvpn_peer_type_e type;

	struct {
		uint32_t outbound_id;
		uint32_t inbound_id;

		uint8_t ephemeral_public[CURVE25519_KEY_SIZE];
		uint8_t ephemeral_private[CURVE25519_KEY_SIZE];

		uint8_t chain_key[BLAKE2S_HASH_SIZE];
		uint8_t hash_key[BLAKE2S_HASH_SIZE];
	} handshake;

	chipvpn_peer_session_t prev_session;
	chipvpn_peer_session_t session;
	chipvpn_peer_session_t next_session;

	chipvpn_address_t address;

	struct {
		chipvpn_address_t address;
		chipvpn_address_t allow;
		chipvpn_firewall_t firewall;
		uint8_t public[CURVE25519_KEY_SIZE];
		uint8_t psk[BLAKE2S_HASH_SIZE];
		char *onconnect;
		char *ondisconnect;
	} config;

	uint8_t timestamp[TAI64N_SIZE];
	uint64_t tx;
	uint64_t rx;
	uint64_t last_check;
	uint64_t next_rekey;
	uint64_t next_ack;
	chipvpn_peer_ack_e ack_state;
} chipvpn_peer_t;

chipvpn_peer_t         *chipvpn_peer_create();

int                     chipvpn_peer_send_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr);
int                     chipvpn_peer_recv_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *socket, chipvpn_packet_auth_t *packet, chipvpn_address_t *addr);
int                     chipvpn_peer_send_auth_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr);
int                     chipvpn_peer_recv_auth_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_packet_auth_reply_t *packet, chipvpn_address_t *addr);

int                     chipvpn_peer_send_keepalive(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *socket);
int                     chipvpn_peer_recv_keepalive(chipvpn_peer_t *peer);

void                    chipvpn_peer_reset_session(chipvpn_peer_t *peer);

bool                    chipvpn_peer_set_allow(chipvpn_peer_t *peer, const char *address, uint8_t prefix);
bool                    chipvpn_peer_set_address(chipvpn_peer_t *peer, const char *address, uint16_t port);
bool                    chipvpn_peer_set_public_key(chipvpn_peer_t *peer, chipvpn_device_t *device, const char *key);
bool                    chipvpn_peer_set_psk(chipvpn_peer_t *peer, const char *key);
bool                    chipvpn_peer_set_onconnect(chipvpn_peer_t *peer, const char *command);
bool                    chipvpn_peer_set_onping(chipvpn_peer_t *peer, const char *command);
bool                    chipvpn_peer_set_ondisconnect(chipvpn_peer_t *peer, const char *command);
chipvpn_peer_t         *chipvpn_peer_get_by_public_key(chipvpn_list_t *peers, uint8_t *public);
chipvpn_peer_t         *chipvpn_peer_get_by_allowip(chipvpn_list_t *peers, chipvpn_address_t *ip);
chipvpn_peer_t         *chipvpn_peer_by_handshake(chipvpn_list_t *peers, uint32_t session_id);
chipvpn_peer_t         *chipvpn_peer_by_session(chipvpn_list_t *peers, chipvpn_peer_session_t **session, uint32_t session_id);
void                    chipvpn_peer_session_promote(chipvpn_peer_t *peer);
void                    chipvpn_peer_set_state(chipvpn_peer_t *peer, chipvpn_peer_state_e state);
void                    chipvpn_peer_run_command(chipvpn_peer_t *peer, const char *command);
void                    chipvpn_peer_service(chipvpn_list_t *peers, chipvpn_device_t *device, chipvpn_udp_t *socket);
bool                    chipvpn_peer_encrypt_payload(chipvpn_peer_session_t *session, uint8_t *data, size_t size, uint64_t counter, uint8_t *mac);
bool                    chipvpn_peer_decrypt_payload(chipvpn_peer_session_t *session, uint8_t *data, size_t size, uint64_t counter, uint8_t *mac);
void                    chipvpn_peer_free(chipvpn_peer_t *peer);

#ifdef __cplusplus
}
#endif

#endif