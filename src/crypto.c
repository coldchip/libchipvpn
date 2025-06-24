#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crypto.h"
#include "chacha20.h"
#include "xchacha20.h"
#include "poly1305.h"

void chipvpn_crypto_set_key(chipvpn_crypto_t *crypto, char *key) {
	memcpy(crypto->key, key, 32);
}

void chipvpn_crypto_set_nonce(chipvpn_crypto_t *crypto, char *nonce) {
	memcpy(crypto->nonce, nonce, 24);
}

void chipvpn_crypto_poly1305_init(chipvpn_crypto_t *crypto) {
	memset(&crypto->block0, 0, sizeof(crypto->block0));
	//xchacha_hchacha20((uint8_t*)&crypto->block0, (uint8_t*)crypto->nonce, (uint8_t*)crypto->key);

	char key2[32] = {0};
	char nonce2[12] = {0};
	xchacha_hchacha20((uint8_t*)key2, (uint8_t*)crypto->nonce, (uint8_t*)crypto->key);


	memcpy(nonce2 + 4, crypto->nonce + 16, 12 - 4);

	struct chacha20_context ctx;
	chacha20_init_context(&ctx, (uint8_t*)key2, (uint8_t*)nonce2, 0);
	chacha20_xor(&ctx, (uint8_t*)&crypto->block0, sizeof(crypto->block0));
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

static const unsigned char _pad0[16] = { 0 };

void chipvpn_crypto_xchacha20_poly1305_encrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	chipvpn_crypto_xchacha20(crypto, data, size, counter);

	poly1305_context ctx;
	poly1305_init(&ctx, (unsigned char*)&crypto->block0);
	poly1305_update(&ctx, (unsigned char*)data, size);
	poly1305_update(&ctx, (unsigned char*)_pad0, (0x10 - size) & 0xf);

	uint64_t aad_size = 0l;
	uint64_t data_size = size;

	poly1305_update(&ctx, (unsigned char*)&aad_size, sizeof(aad_size));
	poly1305_update(&ctx, (unsigned char*)&data_size, sizeof(data_size));

	poly1305_finish(&ctx, (unsigned char*)mac);

}

void chipvpn_crypto_xchacha20_poly1305_decrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	poly1305_context ctx;
	poly1305_init(&ctx, (unsigned char*)&crypto->block0);
	poly1305_update(&ctx, (unsigned char*)data, size);
	poly1305_update(&ctx, (unsigned char*)_pad0, (0x10 - size) & 0xf);

	uint64_t aad_size = 0l;
	uint64_t data_size = size;

	poly1305_update(&ctx, (unsigned char*)&aad_size, sizeof(aad_size));
	poly1305_update(&ctx, (unsigned char*)&data_size, sizeof(data_size));

	poly1305_finish(&ctx, (unsigned char*)mac);

	chipvpn_crypto_xchacha20(crypto, data, size, counter);
}