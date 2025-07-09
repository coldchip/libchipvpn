#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>

typedef struct {
	uint8_t key[32];
} chipvpn_crypto_t;

static const uint8_t pad0[16] = { 0 };

bool                  chipvpn_crypto_chacha20_poly1305_encrypt(chipvpn_crypto_t *crypto, uint8_t *data, int size, uint64_t counter, uint8_t *mac);
bool                  chipvpn_crypto_chacha20_poly1305_decrypt(chipvpn_crypto_t *crypto, uint8_t *data, int size, uint64_t counter, uint8_t *mac);

int                   chipvpn_crypto_memcmp16(const uint8_t *a, const uint8_t *b);

#ifdef __cplusplus
}
#endif

#endif