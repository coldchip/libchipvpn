#include "chacha20.h"

void chacha20_init(chacha20_t *ctx, uint8_t key[], uint8_t nonce[]) {
	ctx->state[0]  = 0x61707865; /* expa */
	ctx->state[1]  = 0x3320646e; /* nd 3 */
	ctx->state[2]  = 0x79622d32; /* 2-by */
	ctx->state[3]  = 0x6b206574; /* te k */
	ctx->state[4]  = PACK4_LE(key + 0 * 4);
	ctx->state[5]  = PACK4_LE(key + 1 * 4);
	ctx->state[6]  = PACK4_LE(key + 2 * 4);
	ctx->state[7]  = PACK4_LE(key + 3 * 4);
	ctx->state[8]  = PACK4_LE(key + 4 * 4);
	ctx->state[9]  = PACK4_LE(key + 5 * 4);
	ctx->state[10] = PACK4_LE(key + 6 * 4);
	ctx->state[11] = PACK4_LE(key + 7 * 4);
	ctx->state[12] = 0u;
	ctx->state[13] = PACK4_LE(nonce + 0 * 4);
	ctx->state[14] = PACK4_LE(nonce + 1 * 4);
	ctx->state[15] = PACK4_LE(nonce + 2 * 4);

	ctx->position = 0;
}

void chacha20_set_counter(chacha20_t *ctx, uint32_t counter) {
	ctx->state[12] = (uint32_t)counter;
	ctx->position = 0;
}

void chacha20_xcrypt_block(chacha20_t *ctx) {
	uint32_t x[16];
	memcpy(x, ctx->state, sizeof(x));

	for(int i = 0; i < 10; i++) {
		CHACHA20_QUARTERROUND(x, 0, 4, 8, 12)
		CHACHA20_QUARTERROUND(x, 1, 5, 9, 13)
		CHACHA20_QUARTERROUND(x, 2, 6, 10, 14)
		CHACHA20_QUARTERROUND(x, 3, 7, 11, 15)
		CHACHA20_QUARTERROUND(x, 0, 5, 10, 15)
		CHACHA20_QUARTERROUND(x, 1, 6, 11, 12)
		CHACHA20_QUARTERROUND(x, 2, 7, 8, 13)
		CHACHA20_QUARTERROUND(x, 3, 4, 9, 14)
	}

	for(int i = 0; i < 16; i++) {
		uint32_t res = PLUS(x[i], ctx->state[i]);
		UNPACK4_LE(ctx->keystream + (i * 4), res);
	}

	ctx->state[12] = PLUS(ctx->state[12], 1);
}

void chacha20_xcrypt(chacha20_t *ctx, uint8_t *bytes, size_t size) {
	while(size > 0) {
		size_t offset = ctx->position & 63;
		if(offset == 0) chacha20_xcrypt_block(ctx);

		size_t chunk = 64 - offset;
		if(chunk > size) chunk = size;

		for(size_t i = 0; i < chunk; i++) {
			bytes[i] ^= ctx->keystream[offset + i];
		}

		bytes += chunk;
		size -= chunk;
		ctx->position += chunk;
	}
}