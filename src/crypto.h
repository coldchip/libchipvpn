#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <sodium.h>

typedef struct {
	char key[crypto_stream_xchacha20_KEYBYTES];
	char nonce[crypto_stream_xchacha20_NONCEBYTES];
} chipvpn_crypto_t;

void                  chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key);
void                  chipvpn_crypto_set_nonce(chipvpn_crypto_t *crypto, char *nonce);
void                  chipvpn_crypto_xchacha20(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter);
void                  chipvpn_crypto_xor(char *dst, char *src, int size, char *key, int klen);

#ifdef __cplusplus
}
#endif

#endif