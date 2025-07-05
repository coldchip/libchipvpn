#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

typedef struct {
	char key[32];
} chipvpn_crypto_t;

static const unsigned char pad0[16] = { 0 };

void                  chipvpn_crypto_chacha20_poly1305_encrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac);
void                  chipvpn_crypto_chacha20_poly1305_decrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac);

int                   chipvpn_crypto_memcmp16(const uint8_t *a, const uint8_t *b);

#ifdef __cplusplus
}
#endif

#endif