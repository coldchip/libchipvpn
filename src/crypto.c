#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <stdint.h>
#include "crypto.h"

void chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key) {
	memcpy(crypto->key, key, crypto_stream_xchacha20_KEYBYTES);
}

void chipvpn_crypto_set_nonce(chipvpn_crypto_t *crypto, char *nonce) {
	memcpy(crypto->nonce, nonce, crypto_stream_xchacha20_NONCEBYTES);
}

void chipvpn_crypto_xcrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter) {
	crypto_stream_xchacha20_xor_ic(
		(unsigned char*)data, 
		(unsigned char*)data, 
		size, 
		(unsigned char*)crypto->nonce, 
		counter, 
		(unsigned char*)crypto->key
	);
}

