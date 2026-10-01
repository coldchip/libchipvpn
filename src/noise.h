#ifndef NOISE_H
#define NOISE_H

#include <stdint.h>
#include <stdbool.h>
#include "curve25519.h"
#include "blake2s.h"

void               chipvpn_noise_init(uint8_t *chain_key, uint8_t *hash_key, const uint8_t *peer_pub);
bool               chipvpn_noise_generate_keypair(uint8_t *public, uint8_t *private);
void               chipvpn_noise_compute_macs(void *packet, size_t auth_len, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub);
void               chipvpn_noise_encrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t len, uint8_t *mac);
bool               chipvpn_noise_decrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t len, uint8_t *mac);
void               chipvpn_blake2s_concat(uint8_t *hash, const uint8_t *src, size_t src_len);

void               chipvpn_noise_kdf1(uint8_t *tau1, const uint8_t *chaining_key, const uint8_t *data, size_t data_len);
void               chipvpn_noise_kdf2(uint8_t *tau1, uint8_t *tau2, const uint8_t *chaining_key, const uint8_t *data, size_t data_len);
void               chipvpn_noise_kdf3(uint8_t *tau1, uint8_t *tau2, uint8_t *tau3, const uint8_t *chaining_key, const uint8_t *data, size_t data_len);

#endif