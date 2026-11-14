#ifndef NOISE_H
#define NOISE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include "curve25519.h"
#include "blake2s.h"
#include "peer.h"

void               chipvpn_noise_init(uint8_t *chain_key, uint8_t *hash_key, const uint8_t *peer_pub);
bool               chipvpn_noise_generate_keypair(uint8_t *public, uint8_t *private);
void               chipvpn_noise_compute_macs(void *packet, size_t size, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub);
bool               chipvpn_noise_verify_macs(void *packet, size_t size, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub);
void               chipvpn_noise_encrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t size, uint8_t *mac);
bool               chipvpn_noise_decrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t size, uint8_t *mac);
void               chipvpn_blake2s_concat(uint8_t *hash, const uint8_t *src, size_t size);

void               chipvpn_noise_kdf(uint8_t *t1, uint8_t *t2, uint8_t *t3, const uint8_t *chain_key, const uint8_t *data, size_t size);

#define            chipvpn_noise_kdf1(t1, chain_key, data, size) chipvpn_noise_kdf((t1), NULL, NULL, (chain_key), (data), (size))
#define            chipvpn_noise_kdf2(t1, t2, chain_key, data, size) chipvpn_noise_kdf((t1), (t2), NULL, (chain_key), (data), (size))
#define            chipvpn_noise_kdf3(t1, t2, t3, chain_key, data, size) chipvpn_noise_kdf((t1), (t2), (t3), (chain_key), (data), (size))

bool               chipvpn_noise_produce_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_packet_auth_t *packet);
chipvpn_peer_t    *chipvpn_noise_consume_connect(const chipvpn_device_t *device, chipvpn_packet_auth_t *packet);
bool               chipvpn_noise_produce_reply(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet);
chipvpn_peer_t    *chipvpn_noise_consume_reply(const chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet);

bool               chipvpn_noise_begin_session(chipvpn_peer_t *peer, bool is_initiator);

#ifdef __cplusplus
}
#endif

#endif