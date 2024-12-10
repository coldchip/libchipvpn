#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crypto.h"
#include "xchacha20.h"

void chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key) {
	memcpy(crypto->key, key, 32);
}

void chipvpn_crypto_set_nonce(chipvpn_crypto_t *crypto, char *nonce) {
	memcpy(crypto->nonce, nonce, 24);
}

void chipvpn_crypto_xchacha20(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter) {
	xchacha_xcrypt(
		(unsigned char*)data, 
		(unsigned char*)data, 
		size, 
		(unsigned char*)crypto->key,
		(unsigned char*)crypto->nonce, 
		counter
	);
}