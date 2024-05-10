#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

typedef struct {
	char key[256 / 8];
	char nonce[192 / 8];
} chipvpn_crypto_t;

void                  chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key);
void                  chipvpn_crypto_set_nonce(chipvpn_crypto_t *crypto, char *nonce);
void                  chipvpn_crypto_xchacha20(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter);
void                  chipvpn_crypto_xor(char *dst, char *src, int size, char *key, int klen);
void                  chipvpn_crypto_crc32_init(uint32_t *state);
void                  chipvpn_crypto_crc32_update(uint32_t *state, const void *buf, size_t size);
uint32_t              chipvpn_crypto_crc32_final(uint32_t *state);

#ifdef __cplusplus
}
#endif

#endif