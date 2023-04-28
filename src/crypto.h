#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

typedef struct {
	char key[32];
	int keylength;
} chipvpn_crypto_t;

chipvpn_crypto_t     *chipvpn_crypto_create();
void                  chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key);
void                  chipvpn_crypto_xcrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter);
void                  chipvpn_crypto_free(chipvpn_crypto_t *crypto);

#endif