#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "chacha20poly1305.h"
#include "chacha20.h"
#include "poly1305.h"

void chipvpn_crypto_chacha20_poly1305_encrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	char nonce[12] = {0};
	memcpy(nonce + 4, &counter, sizeof(counter));

	struct chacha20_context chacha20_ctx;
	chacha20_init_context(&chacha20_ctx, (uint8_t*)crypto->key, (uint8_t*)nonce, 0);

	char block0[64] = {0};
	chacha20_xor(&chacha20_ctx, (uint8_t*)block0, sizeof(block0));

	chacha20_xor(&chacha20_ctx, (uint8_t*)data, size);

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
	char nonce[12] = {0};
	memcpy(nonce + 4, &counter, sizeof(counter));

	struct chacha20_context chacha20_ctx;
	chacha20_init_context(&chacha20_ctx, (uint8_t*)crypto->key, (uint8_t*)nonce, 0);

	char block0[64] = {0};
	chacha20_xor(&chacha20_ctx, (uint8_t*)block0, sizeof(block0));

	poly1305_context poly1305_ctx;
	poly1305_init(&poly1305_ctx, (unsigned char*)&block0);
	poly1305_update(&poly1305_ctx, (unsigned char*)data, size);
	poly1305_update(&poly1305_ctx, (unsigned char*)_pad0, (0x10 - size) & 0xf);

	uint64_t aad_size = 0l;
	uint64_t data_size = size;

	poly1305_update(&poly1305_ctx, (unsigned char*)&aad_size, sizeof(aad_size));
	poly1305_update(&poly1305_ctx, (unsigned char*)&data_size, sizeof(data_size));

	poly1305_finish(&poly1305_ctx, (unsigned char*)mac);

	chacha20_xor(&chacha20_ctx, (uint8_t*)data, size);
}

int chipvpn_crypto_memcmp16(const uint8_t *a, const uint8_t *b) {
    uint8_t diff = 0;

    diff |= a[0] ^ b[0];
    diff |= a[1] ^ b[1];
    diff |= a[2] ^ b[2];
    diff |= a[3] ^ b[3];
    diff |= a[4] ^ b[4];
    diff |= a[5] ^ b[5];
    diff |= a[6] ^ b[6];
    diff |= a[7] ^ b[7];
    diff |= a[8] ^ b[8];
    diff |= a[9] ^ b[9];
    diff |= a[10] ^ b[10];
    diff |= a[11] ^ b[11];
    diff |= a[12] ^ b[12];
    diff |= a[13] ^ b[13];
    diff |= a[14] ^ b[14];
    diff |= a[15] ^ b[15];

    return diff;
}