#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>

#define CHACHA20_KEY_SIZE 32

static const uint8_t pad0[16] = { 0 };

bool                  chipvpn_crypto_chacha20_poly1305_encrypt(uint8_t *key, uint8_t *data, int size, uint64_t counter, uint8_t *mac);
bool                  chipvpn_crypto_chacha20_poly1305_decrypt(uint8_t *key, uint8_t *data, int size, uint64_t counter, uint8_t *mac);

#ifdef __cplusplus
}
#endif

#endif