#include "chacha20.h"

static void chacha20_init_block(chacha20_t *ctx, uint8_t key[], uint8_t nonce[]) {
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
    ctx->state[12] = 0;
    ctx->state[13] = PACK4_LE(nonce + 0 * 4);
    ctx->state[14] = PACK4_LE(nonce + 1 * 4);
    ctx->state[15] = PACK4_LE(nonce + 2 * 4);
}

static void chacha20_block_set_counter(chacha20_t *ctx, uint32_t counter) {
    ctx->state[12] = (uint32_t)counter;
}

static void chacha20_block_next(chacha20_t *ctx) {
    #if defined(__ARM_NEON) || defined(__ARM_NEON__)
    /* 1. Load the 4x4 matrix into four 128-bit NEON row registers */
    uint32x4_t s0 = vld1q_u32(&ctx->state[0]);
    uint32x4_t s1 = vld1q_u32(&ctx->state[4]);
    uint32x4_t s2 = vld1q_u32(&ctx->state[8]);
    uint32x4_t s3 = vld1q_u32(&ctx->state[12]);

    uint32x4_t r0 = s0;
    uint32x4_t r1 = s1;
    uint32x4_t r2 = s2;
    uint32x4_t r3 = s3;

    for (int i = 0; i < 10; i++) {
        /* 2. Compute ALL 4 columns instantly */
        CHACHA20_QUARTERROUND_NEON(r0, r1, r2, r3);

        /* 3. Shift the rows to line up the diagonals */
        r1 = vextq_u32(r1, r1, 1);
        r2 = vextq_u32(r2, r2, 2);
        r3 = vextq_u32(r3, r3, 3);

        /* 4. Compute ALL 4 diagonals instantly */
        CHACHA20_QUARTERROUND_NEON(r0, r1, r2, r3);

        /* 5. Shift the rows back */
        r1 = vextq_u32(r1, r1, 3);
        r2 = vextq_u32(r2, r2, 2);
        r3 = vextq_u32(r3, r3, 1);
    }

    /* 6. Add initial state and store directly to keystream */
    vst1q_u32(&ctx->keystream[0],  vaddq_u32(r0, s0));
    vst1q_u32(&ctx->keystream[4],  vaddq_u32(r1, s1));
    vst1q_u32(&ctx->keystream[8],  vaddq_u32(r2, s2));
    vst1q_u32(&ctx->keystream[12], vaddq_u32(r3, s3));
#else
    memcpy(ctx->keystream, ctx->state, 64);

    for(int i = 0; i < 10; i++) {
        CHACHA20_QUARTERROUND(ctx->keystream, 0, 4, 8, 12)
        CHACHA20_QUARTERROUND(ctx->keystream, 1, 5, 9, 13)
        CHACHA20_QUARTERROUND(ctx->keystream, 2, 6, 10, 14)
        CHACHA20_QUARTERROUND(ctx->keystream, 3, 7, 11, 15)
        CHACHA20_QUARTERROUND(ctx->keystream, 0, 5, 10, 15)
        CHACHA20_QUARTERROUND(ctx->keystream, 1, 6, 11, 12)
        CHACHA20_QUARTERROUND(ctx->keystream, 2, 7, 8, 13)
        CHACHA20_QUARTERROUND(ctx->keystream, 3, 4, 9, 14)
    }

    for(int i = 0; i < 16; i++) {
        ctx->keystream[i] = PLUS(ctx->keystream[i], ctx->state[i]);
    }
#endif

    ctx->state[12] = PLUS(ctx->state[12], 1);
}

void chacha20_init_context(chacha20_t *ctx, uint8_t *key, uint8_t *nonce, uint32_t counter) {
    chacha20_init_block(ctx, key, nonce);
    chacha20_block_set_counter(ctx, counter);

    ctx->position = 0;
}

void chacha20_xor(chacha20_t *ctx, uint8_t *bytes, size_t size) {
    uint8_t *keystream = (uint8_t*)ctx->keystream;

    while(size > 0) {
        size_t offset = ctx->position & 63;
        if(offset == 0) {
            chacha20_block_next(ctx);
        }

        size_t chunk = 64 - offset;
        if(chunk > size) chunk = size;

        for(size_t i = 0; i < chunk; i++) {
            bytes[i] ^= keystream[offset + i];
        }

        bytes += chunk;
        size -= chunk;
        ctx->position += chunk;
    }
}

void chacha20_xcrypt(uint8_t *key, uint8_t *nonce, uint8_t *bytes, size_t size) {
    chacha20_t chacha20_ctx;
    chacha20_init_context(&chacha20_ctx, (uint8_t*)key, (uint8_t*)nonce, 0);
    chacha20_xor(&chacha20_ctx, bytes, size);
}