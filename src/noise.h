#ifndef NOISE_H
#define NOISE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "curve25519.h"
#include "blake2s.h"
#include "peer.h"

enum {
	CHIPVPN_NOISE_OK = 0,
	CHIPVPN_NOISE_ERR_INDEX,
	CHIPVPN_NOISE_ERR_RNG,
	CHIPVPN_NOISE_ERR_MAC,
	CHIPVPN_NOISE_ERR_DH,
	CHIPVPN_NOISE_ERR_AEAD,
	CHIPVPN_NOISE_ERR_TIMESTAMP,
	CHIPVPN_NOISE_ERR_UNKNOWN_PEER,
	CHIPVPN_NOISE_ERR_UNKNOWN_HANDSHAKE
};

void           chipvpn_noise_init(uint8_t *chain_key, uint8_t *hash_key, const uint8_t *peer_pub);
bool           chipvpn_noise_generate_keypair(uint8_t *public_key, uint8_t *private_key);
void           chipvpn_noise_compute_macs(const void *packet, size_t size, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub);
bool           chipvpn_noise_verify_macs(const void *packet, size_t size, const uint8_t *mac1, const uint8_t *mac2, const uint8_t *peer_pub);
bool           chipvpn_noise_encrypt_and_mix(uint8_t *hash_key, const uint8_t *cipher_key, uint8_t *data, size_t size, uint8_t *mac);
bool           chipvpn_noise_decrypt_and_mix(uint8_t *hash_key, const uint8_t *cipher_key, uint8_t *data, size_t size, const uint8_t *mac);
void           chipvpn_blake2s_concat(uint8_t *hash, const uint8_t *src, size_t size);

void           chipvpn_noise_kdf(uint8_t *t1, uint8_t *t2, uint8_t *t3, const uint8_t *chain_key, const uint8_t *data, size_t size);

#define        chipvpn_noise_kdf1(t1, chain_key, data, size) chipvpn_noise_kdf((t1), NULL, NULL, (chain_key), (data), (size))
#define        chipvpn_noise_kdf2(t1, t2, chain_key, data, size) chipvpn_noise_kdf((t1), (t2), NULL, (chain_key), (data), (size))
#define        chipvpn_noise_kdf3(t1, t2, t3, chain_key, data, size) chipvpn_noise_kdf((t1), (t2), (t3), (chain_key), (data), (size))

int            chipvpn_noise_produce_connect(chipvpn_device_t *device, chipvpn_peer_t *peer, chipvpn_packet_auth_t *packet);
int            chipvpn_noise_consume_connect(chipvpn_device_t *device, chipvpn_peer_t **peer_out, chipvpn_packet_auth_t *packet, uint8_t *static_public_out);
int            chipvpn_noise_produce_reply(chipvpn_device_t *device, chipvpn_peer_t *peer, chipvpn_packet_auth_reply_t *packet);
int            chipvpn_noise_consume_reply(chipvpn_device_t *device, chipvpn_peer_t **peer_out, chipvpn_packet_auth_reply_t *packet);

void           chipvpn_noise_begin_session(chipvpn_peer_t *peer, bool is_initiator);

#ifdef __cplusplus
}
#endif

#endif