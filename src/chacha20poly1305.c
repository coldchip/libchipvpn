#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "chacha20poly1305.h"
#include "chacha20.h"
#include "poly1305.h"
#include "util.h"

bool chipvpn_crypto_chacha20_poly1305_encrypt(chipvpn_crypto_t *crypto, uint8_t *data, int size, uint64_t counter, uint8_t *mac) {
	struct chacha20_context chacha20_ctx;
	poly1305_context poly1305_ctx;
	uint8_t  nonce[12];
	uint8_t  block0[64];
	uint64_t aad_size = 0l;
	uint64_t data_size = size;

	// Create 96bit nonce from 64bit counter by copying to 32-96bit region 
	memset(nonce, 0, 4);
	memcpy(nonce + 4, &counter, sizeof(counter));

	// Initialize chacha20 from key and nonce
	chacha20_init_context(&chacha20_ctx, (uint8_t*)crypto->key, (uint8_t*)nonce, 0);

	// Generate poly1305 key from key and nonce, internal counter = 0
	chacha20_xor(&chacha20_ctx, (uint8_t*)block0, sizeof(block0));

	// Encrypt payload, internal counter = 1..2.. and so on
	chacha20_xor(&chacha20_ctx, (uint8_t*)data, size);

	// Update poly1305 with data and padding
	poly1305_init(&poly1305_ctx, (unsigned char*)&block0);
	poly1305_update(&poly1305_ctx, (unsigned char*)data, size);
	poly1305_update(&poly1305_ctx, (unsigned char*)pad0, (0x10 - size) & 0xf);

	// Update poly1305 with aad(not needed) and size
	poly1305_update(&poly1305_ctx, (unsigned char*)&aad_size, sizeof(aad_size));
	poly1305_update(&poly1305_ctx, (unsigned char*)&data_size, sizeof(data_size));

	// Compute poly1305 and output to mac
	poly1305_finish(&poly1305_ctx, (unsigned char*)mac);

	return true;
}

bool chipvpn_crypto_chacha20_poly1305_decrypt(chipvpn_crypto_t *crypto, uint8_t *data, int size, uint64_t counter, uint8_t *mac) {
	struct chacha20_context chacha20_ctx;
	poly1305_context poly1305_ctx;
	uint8_t  computed_mac[16];
	uint8_t  nonce[12];
	uint8_t  block0[64];
	uint64_t aad_size = 0l;
	uint64_t data_size = size;

	// Create 96bit nonce from 64bit counter by copying to 32-96bit region 
	memset(nonce, 0, 4);
	memcpy(nonce + 4, &counter, sizeof(counter));

	// Initialize chacha20 from key and nonce
	chacha20_init_context(&chacha20_ctx, (uint8_t*)crypto->key, (uint8_t*)nonce, 0);

	// Generate poly1305 key from key and nonce, internal counter = 0
	chacha20_xor(&chacha20_ctx, (uint8_t*)block0, sizeof(block0));

	// Update poly1305 with data and padding
	poly1305_init(&poly1305_ctx, (unsigned char*)&block0);
	poly1305_update(&poly1305_ctx, (unsigned char*)data, size);
	poly1305_update(&poly1305_ctx, (unsigned char*)pad0, (0x10 - size) & 0xf);

	// Update poly1305 with aad(not needed) and size
	poly1305_update(&poly1305_ctx, (unsigned char*)&aad_size, sizeof(aad_size));
	poly1305_update(&poly1305_ctx, (unsigned char*)&data_size, sizeof(data_size));

	// Compute poly1305 and output to mac
	poly1305_finish(&poly1305_ctx, (unsigned char*)computed_mac);

	// Compare computed mac against input mac
	if(chipvpn_secure_memcmp((uint8_t*)computed_mac, (uint8_t*)mac, 16) != 0) {
		return false;
	}

	// Finally, if mac matches, decrypt payload, internal counter = 1..2.. and so on
	chacha20_xor(&chacha20_ctx, (uint8_t*)data, size);

	return true;
}