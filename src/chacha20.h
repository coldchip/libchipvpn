#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus 
extern "C" {
#endif

#define U8V(v) ((uint8_t)(v) & (0xFF))
#define U16V(v) ((uint16_t)(v) & (0xFFFF))
#define U32V(v) ((uint32_t)(v) & (0xFFFFFFFF))
#define U64V(v) ((uint64_t)(v) & (0xFFFFFFFFFFFFFFFF))

#define PACK4_LE(p) \
	(((uint32_t)((p)[0])     ) | \
	((uint32_t)((p)[1]) <<  8) | \
	((uint32_t)((p)[2]) << 16) | \
	((uint32_t)((p)[3]) << 24))

#define ROTL32(v, n) \
	(U32V((v) << (n)) | ((v) >> (32 - (n))))

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
	x[a] = PLUS(x[a], x[b]); x[d] = ROTATE(XOR(x[d], x[a]), 16); \
	x[c] = PLUS(x[c], x[d]); x[b] = ROTATE(XOR(x[b], x[c]), 12); \
	x[a] = PLUS(x[a], x[b]); x[d] = ROTATE(XOR(x[d], x[a]), 8); \
	x[c] = PLUS(x[c], x[d]); x[b] = ROTATE(XOR(x[b], x[c]), 7);

struct chacha20_context {
	uint32_t keystream[16];
	uint32_t state[16];
	size_t position;
};

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nounc[], uint32_t counter);
void chacha20_block_set_nonce(struct chacha20_context *ctx, uint8_t nonce[]);
void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t size);

#ifdef __cplusplus 
}
#endif 