#ifndef CRYPTO_H
#define CRYPTO_H

typedef struct {
	int todo;
} chipvpn_crypto_t;

chipvpn_crypto_t     *chipvpn_crypto_create();
void                  chipvpn_crypto_xcrypt(void *data, int size);
void                  chipvpn_crypto_free(chipvpn_crypto_t *crypto);

#endif