#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus 
extern "C" {
#endif

struct chacha20_ctx {
    uint32_t input[16];
};

typedef struct chacha20_ctx chacha20_ctx;

# define ROTL32(X, B) rotl32((X), (B))
static inline uint32_t
rotl32(const uint32_t x, const int b)
{
    return (x << b) | (x >> (32 - b));
}

#define LOAD32_LE(SRC) load32_le(SRC)
static inline uint32_t
load32_le(const uint8_t src[4])
{
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

#define STORE32_LE(DST, W) store32_le((DST), (W))
static inline void
store32_le(uint8_t dst[4], uint32_t w)
{
    memcpy(dst, &w, sizeof w);
}

#define U32C(v) (v##U)
#define U32V(v) ((uint32_t)(v) &U32C(0xFFFFFFFF))

#define ROTATE(v, c) (ROTL32(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

#define QUARTERROUND(a, b, c, d) \
    a = PLUS(a, b);              \
    d = ROTATE(XOR(d, a), 16);   \
    c = PLUS(c, d);              \
    b = ROTATE(XOR(b, c), 12);   \
    a = PLUS(a, b);              \
    d = ROTATE(XOR(d, a), 8);    \
    c = PLUS(c, d);              \
    b = ROTATE(XOR(b, c), 7);


void chacha_keysetup(chacha20_ctx *ctx, const uint8_t *k);
void chacha_ivsetup(chacha20_ctx *ctx, const uint8_t *iv, const uint8_t *counter);
void chacha20_encrypt_bytes(chacha20_ctx *ctx, const uint8_t *m, uint8_t *c, unsigned long long bytes);

#ifdef __cplusplus 
}
#endif 