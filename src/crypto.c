#include <stdlib.h>
#include <string.h>
#include "crypto.h"

chipvpn_crypto_t *chipvpn_crypto_create() {
	chipvpn_crypto_t *crypto = malloc(sizeof(chipvpn_crypto_t));
	if(!crypto) {
		return NULL;
	}
	strcpy(crypto->key, "default");
	return crypto;
}

void chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key) {
	strcpy(crypto->key, key);
}

void chipvpn_crypto_xcrypt(chipvpn_crypto_t *crypto, void *data, int size) {
	int keylen = strlen(crypto->key);

	for(int i = 0; i < size; ++i) {
		*((char*)data + i) ^= crypto->key[i % keylen];
	}
}

void chipvpn_crypto_free(chipvpn_crypto_t *crypto) {
	free(crypto);
}