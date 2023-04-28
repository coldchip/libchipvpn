#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <stdint.h>
#include "crypto.h"

char nounce[] = {
	0xce, 0x83, 0x43, 0x3e, 0x2e, 0x50, 0x7b, 0x0d 
};

chipvpn_crypto_t *chipvpn_crypto_create() {
	chipvpn_crypto_t *crypto = malloc(sizeof(chipvpn_crypto_t));
	if(!crypto) {
		return NULL;
	}
	memset(crypto->key, 0, sizeof(crypto->key));

	return crypto;
}

void chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key) {
	crypto_hash_sha256((unsigned char*)crypto->key, (unsigned char*)key, strlen(key));
}

void chipvpn_crypto_xcrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter) {
	crypto_stream_chacha20_xor_ic(
		(unsigned char*)data, 
		(unsigned char*)data, 
		size, 
		(unsigned char*)nounce, 
		counter, 
		(unsigned char*)crypto->key
	);
}

void chipvpn_crypto_free(chipvpn_crypto_t *crypto) {
	free(crypto);
}