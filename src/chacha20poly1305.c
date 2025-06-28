#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "chacha20poly1305.h"
#include "chacha20.h"
#include "poly1305.h"

void chipvpn_crypto_chacha20_poly1305_encrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	char nonce[12];
	memset(nonce, 0, sizeof(nonce));
	memcpy(nonce + 4, &counter, sizeof(counter));

	//struct chacha20_context chacha20_ctx;
	//chacha20_init_context(&chacha20_ctx, (uint8_t*)crypto->key, (uint8_t*)nonce, 0);

	char block0[64];
	memset(block0, 0, sizeof(block0));
	//chacha20_xor(&chacha20_ctx, (uint8_t*)block0, sizeof(block0));

	//chacha20_xor(&chacha20_ctx, (uint8_t*)data, size);

	poly1305_context poly1305_ctx;
	poly1305_init(&poly1305_ctx, (unsigned char*)&block0);
	poly1305_update(&poly1305_ctx, (unsigned char*)data, size);
	poly1305_update(&poly1305_ctx, (unsigned char*)_pad0, (0x10 - size) & 0xf);

	uint64_t aad_size = 0l;
	uint64_t data_size = size;

	poly1305_update(&poly1305_ctx, (unsigned char*)&aad_size, sizeof(aad_size));
	poly1305_update(&poly1305_ctx, (unsigned char*)&data_size, sizeof(data_size));

	poly1305_finish(&poly1305_ctx, (unsigned char*)mac);
}

void chipvpn_crypto_chacha20_poly1305_decrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	char nonce[12];
	memset(nonce, 0, sizeof(nonce));
	memcpy(nonce + 4, &counter, sizeof(counter));

	//struct chacha20_context chacha20_ctx;
	//chacha20_init_context(&chacha20_ctx, (uint8_t*)crypto->key, (uint8_t*)nonce, 0);

	char block0[64];
	memset(block0, 0, sizeof(block0));
	//chacha20_xor(&chacha20_ctx, (uint8_t*)block0, sizeof(block0));

	poly1305_context poly1305_ctx;
	poly1305_init(&poly1305_ctx, (unsigned char*)&block0);
	poly1305_update(&poly1305_ctx, (unsigned char*)data, size);
	poly1305_update(&poly1305_ctx, (unsigned char*)_pad0, (0x10 - size) & 0xf);

	uint64_t aad_size = 0l;
	uint64_t data_size = size;

	poly1305_update(&poly1305_ctx, (unsigned char*)&aad_size, sizeof(aad_size));
	poly1305_update(&poly1305_ctx, (unsigned char*)&data_size, sizeof(data_size));

	poly1305_finish(&poly1305_ctx, (unsigned char*)mac);

	//chacha20_xor(&chacha20_ctx, (uint8_t*)data, size);
}