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
	chacha20_init_context(&chacha20_ctx, (uint8_t*)crypto->key, (uint8_t*)nonce, 1);

	chacha20_xor(&chacha20_ctx, (uint8_t*)data, size);

}

void chipvpn_crypto_chacha20_poly1305_decrypt(chipvpn_crypto_t *crypto, void *data, int size, uint64_t counter, char *mac) {
	char nonce[12] = {0};
	memcpy(nonce + 4, &counter, sizeof(counter));

	struct chacha20_context chacha20_ctx;
	chacha20_init_context(&chacha20_ctx, (uint8_t*)crypto->key, (uint8_t*)nonce, 1);

	chacha20_xor(&chacha20_ctx, (uint8_t*)data, size);
}