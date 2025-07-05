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

#if defined(__x86_64__)
	#define CHACHA20_QUARTERROUND(x, a, b, c, d) chacha20_quarterround_x86(x, a, b, c, d);
#elif defined(__aarch64__)
	#define CHACHA20_QUARTERROUND(x, a, b, c, d) chacha20_quarterround_arm64(x, a, b, c, d);
#else
	#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
		x[a] = PLUS(x[a], x[b]); x[d] = ROTATE(XOR(x[d], x[a]), 16); \
		x[c] = PLUS(x[c], x[d]); x[b] = ROTATE(XOR(x[b], x[c]), 12); \
		x[a] = PLUS(x[a], x[b]); x[d] = ROTATE(XOR(x[d], x[a]), 8); \
		x[c] = PLUS(x[c], x[d]); x[b] = ROTATE(XOR(x[b], x[c]), 7);
#endif

struct chacha20_context {
	uint32_t keystream[16];
	uint32_t state[16];
	size_t position;
};

static inline void chacha20_quarterround_x86(uint32_t x[16], int a, int b, int c, int d) {
    __asm__ __volatile__ (
        // x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL(x[d], 16)
        "add %[xb], %[xa]\n\t"
        "xor %[xa], %[xd]\n\t"
        "rol $16, %[xd]\n\t"

        // x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL(x[b], 12)
        "add %[xd], %[xc]\n\t"
        "xor %[xc], %[xb]\n\t"
        "rol $12, %[xb]\n\t"

        // x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL(x[d], 8)
        "add %[xb], %[xa]\n\t"
        "xor %[xa], %[xd]\n\t"
        "rol $8, %[xd]\n\t"

        // x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL(x[b], 7)
        "add %[xd], %[xc]\n\t"
        "xor %[xc], %[xb]\n\t"
        "rol $7, %[xb]\n\t"
        : [xa] "+r" (x[a]),
          [xb] "+r" (x[b]),
          [xc] "+r" (x[c]),
          [xd] "+r" (x[d])
        :
        : "cc"
    );

    // Write back the updated values
    x[a] = x[a];
    x[b] = x[b];
    x[c] = x[c];
    x[d] = x[d];
}

static inline void chacha20_quarterround_arm64(uint32_t x[16], int a, int b, int c, int d) {
    __asm__ __volatile__ (
        // x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL(x[d], 16)
        "add %w[xa], %w[xa], %w[xb]\n\t"
        "eor %w[xd], %w[xd], %w[xa]\n\t"
        "ror %w[xd], %w[xd], #16\n\t"

        // x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL(x[b], 12)
        "add %w[xc], %w[xc], %w[xd]\n\t"
        "eor %w[xb], %w[xb], %w[xc]\n\t"
        "ror %w[xb], %w[xb], #20\n\t" // ROTL 12 = ROR 20

        // x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL(x[d], 8)
        "add %w[xa], %w[xa], %w[xb]\n\t"
        "eor %w[xd], %w[xd], %w[xa]\n\t"
        "ror %w[xd], %w[xd], #24\n\t" // ROTL 8 = ROR 24

        // x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL(x[b], 7)
        "add %w[xc], %w[xc], %w[xd]\n\t"
        "eor %w[xb], %w[xb], %w[xc]\n\t"
        "ror %w[xb], %w[xb], #25\n\t" // ROTL 7 = ROR 25
        : [xa] "+r" (x[a]),
          [xb] "+r" (x[b]),
          [xc] "+r" (x[c]),
          [xd] "+r" (x[d])
        :
        : "cc"
    );
}

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nounc[], uint32_t counter);
void chacha20_block_set_nonce(struct chacha20_context *ctx, uint8_t nonce[]);
void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t size);

#ifdef __cplusplus 
}
#endif 