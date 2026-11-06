#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 12
#define CHACHA20_POLY1305_ENC_LEN(plain_len) ((plain_len) + POLY1305_MAC_SIZE)
#define CHACHA20_POLY1305_DEC_LEN(plain_len) ((plain_len) - POLY1305_MAC_SIZE)

bool chipvpn_crypto_chacha20_poly1305_encrypt(const uint8_t *key, uint8_t *data, size_t data_size, uint64_t counter, const uint8_t *aad, size_t aad_size, uint8_t *mac);
bool chipvpn_crypto_chacha20_poly1305_decrypt(const uint8_t *key, uint8_t *data, size_t data_size, uint64_t counter, const uint8_t *aad, size_t aad_size, const uint8_t *mac);

#ifdef __cplusplus
}
#endif

#endif