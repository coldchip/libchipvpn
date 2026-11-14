// blake2s.h
// BLAKE2s Hashing Context and API Prototypes

#ifndef BLAKE2S_H
#define BLAKE2S_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>

#define BLAKE2S_BLOCK_SIZE 64
#define BLAKE2S_HASH_SIZE 32

// Cyclic right rotation.

#ifndef ROTR32
#define ROTR32(x, y)  (((x) >> (y)) ^ ((x) << (32 - (y))))
#endif

// Little-endian byte access.

#define B2S_GET32(p)                            \
	(((uint32_t) ((uint8_t *) (p))[0]) ^        \
	(((uint32_t) ((uint8_t *) (p))[1]) << 8) ^  \
	(((uint32_t) ((uint8_t *) (p))[2]) << 16) ^ \
	(((uint32_t) ((uint8_t *) (p))[3]) << 24))

// Mixing function G.

#define B2S_G(a, b, c, d, x, y) {   \
	v[a] = v[a] + v[b] + x;         \
	v[d] = ROTR32(v[d] ^ v[a], 16); \
	v[c] = v[c] + v[d];             \
	v[b] = ROTR32(v[b] ^ v[c], 12); \
	v[a] = v[a] + v[b] + y;         \
	v[d] = ROTR32(v[d] ^ v[a], 8);  \
	v[c] = v[c] + v[d];             \
	v[b] = ROTR32(v[b] ^ v[c], 7); }

// state context
typedef struct {
	uint8_t b[64];                      // input buffer
	uint32_t h[8];                      // chained state
	uint32_t t[2];                      // total number of bytes
	size_t c;                           // pointer for b[]
	size_t outlen;                      // digest size
} blake2s_ctx;

int       blake2s_init(blake2s_ctx *ctx, size_t outlen, const void *key, size_t keylen);
void      blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen);
void      blake2s_final(blake2s_ctx *ctx, void *out);
int       blake2s(void *out, size_t outlen, const void *key, size_t keylen, const void *in, size_t inlen);
void      blake2s_hmac(uint8_t *digest, const uint8_t *key, size_t key_len, const uint8_t *text, size_t text_len);

#ifdef __cplusplus 
}
#endif 

#endif