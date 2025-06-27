#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crypto.h"
#include "xchacha20.h"
#include "poly1305.h"

void chipvpn_crypto_xchacha20(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter) {
	
}

void chipvpn_crypto_xchacha20_poly1305_encrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	char nonce[12];
	memset(nonce, 0, sizeof(nonce));
	memcpy(nonce + 4, &counter, sizeof(counter));

	char block0[64];
	chacha20_xor2(block0, sizeof(block0), crypto->key, nonce, 0);

	chacha20_xor2(data, size, crypto->key, nonce, 1);

	poly1305_context ctx;
	poly1305_init(&ctx, (unsigned char*)&crypto->block0);
	poly1305_update(&ctx, (unsigned char*)data, size);
	poly1305_update(&ctx, (unsigned char*)_pad0, (0x10 - size) & 0xf);

	uint64_t data_size = size;

	poly1305_update(&ctx, (unsigned char*)&counter, sizeof(counter));
	poly1305_update(&ctx, (unsigned char*)&data_size, sizeof(data_size));

	poly1305_finish(&ctx, (unsigned char*)mac);
}

void chipvpn_crypto_xchacha20_poly1305_decrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	char nonce[12];
	memset(nonce, 0, sizeof(nonce));
	memcpy(nonce + 4, &counter, sizeof(counter));

	char block0[64];
	chacha20_xor2(block0, sizeof(block0), crypto->key, nonce, 0);

	poly1305_context ctx;
	poly1305_init(&ctx, (unsigned char*)&crypto->block0);
	poly1305_update(&ctx, (unsigned char*)data, size);
	poly1305_update(&ctx, (unsigned char*)_pad0, (0x10 - size) & 0xf);

	uint64_t data_size = size;

	poly1305_update(&ctx, (unsigned char*)&counter, sizeof(counter));
	poly1305_update(&ctx, (unsigned char*)&data_size, sizeof(data_size));

	poly1305_finish(&ctx, (unsigned char*)mac);

	chacha20_xor2(data, size, crypto->key, nonce, 1);
}