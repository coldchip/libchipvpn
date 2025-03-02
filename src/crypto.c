#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crypto.h"
#include "xchacha20.h"
#include "poly1305.h"

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

void chipvpn_crypto_xchacha20_poly1305_encrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	chipvpn_crypto_xchacha20(crypto, data, size, counter);

	poly1305_context poly1305;

	unsigned char block0[64] = {0};

	chipvpn_crypto_xchacha20(crypto, block0, sizeof(block0), counter);

	poly1305_init(&poly1305, block0);
	poly1305_update(&poly1305, data, size);
	poly1305_finish(&poly1305, (unsigned char*)mac);
}

void chipvpn_crypto_xchacha20_poly1305_decrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	poly1305_context poly1305;

	unsigned char block0[64] = {0};

	chipvpn_crypto_xchacha20(crypto, block0, sizeof(block0), counter);

	poly1305_init(&poly1305, block0);
	poly1305_update(&poly1305, data, size);
	poly1305_finish(&poly1305, (unsigned char*)mac);

	chipvpn_crypto_xchacha20(crypto, data, size, counter);
}