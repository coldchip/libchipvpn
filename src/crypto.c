#include <stdlib.h>
#include "crypto.h"

chipvpn_crypto_t *chipvpn_crypto_create() {
	chipvpn_crypto_t *crypto = malloc(sizeof(chipvpn_crypto_t));
	if(!crypto) {
		return NULL;
	}
	crypto->key[0] = '\0';
	return crypto;
}

void chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key) {
	strcpy(crypto->key, key);
}

void chipvpn_crypto_xcrypt(chipvpn_crypto_t *crypto, void *data, int size) {
	for(int i = 0; i < size; ++i) {
		*((char*)data + i) ^= crypto->key[i % strlen(crypto->key)];
	}
}

void chipvpn_crypto_free(chipvpn_crypto_t *crypto) {
	free(crypto);
}