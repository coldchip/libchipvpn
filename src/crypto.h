#ifndef CRYPTO_H
#define CRYPTO_H

typedef struct {
	char key[1024];
} chipvpn_crypto_t;

chipvpn_crypto_t     *chipvpn_crypto_create();
void                  chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key);
void                  chipvpn_crypto_xcrypt(chipvpn_crypto_t *crypto, void *data, int size);
void                  chipvpn_crypto_free(chipvpn_crypto_t *crypto);

#endif