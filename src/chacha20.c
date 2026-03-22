#include "chacha20.h"

static void chacha20_init_block(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[]) {
    ctx->state[0]  = 0x61707865;
    ctx->state[1]  = 0x3320646e;
    ctx->state[2]  = 0x79622d32;
    ctx->state[3]  = 0x6b206574;
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

static void chacha20_block_set_counter(struct chacha20_context *ctx, uint32_t counter) {
    ctx->state[12] = (uint32_t)counter;
}

static void chacha20_block_next(struct chacha20_context *ctx) {
    for(int i = 0; i < 16; i++) ctx->keystream[i] = ctx->state[i];

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

    for(int i = 0; i < 16; i++) ctx->keystream[i] = PLUS(ctx->keystream[i], ctx->state[i]);

    ctx->state[12] = PLUS(ctx->state[12], 1);
}

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[], uint32_t counter) {
    chacha20_init_block(ctx, key, nonce);
    chacha20_block_set_counter(ctx, counter);

    ctx->position = 0;
}


#ifdef HAVE_NEON

#define CHACHA20_BLOCK_SIZE 64

void chacha20_doneon(uint32_t *state, uint8_t *dst, const uint8_t *src, unsigned int bytes) {
    uint8_t buf[CHACHA20_BLOCK_SIZE];
    while (bytes >= CHACHA20_BLOCK_SIZE * 4) {
        chacha20_4block_xor_neon(state, dst, src);
        bytes -= CHACHA20_BLOCK_SIZE * 4;
        src += CHACHA20_BLOCK_SIZE * 4;
        dst += CHACHA20_BLOCK_SIZE * 4;
        state[12] += 4;
    }
    while (bytes >= CHACHA20_BLOCK_SIZE) {
        chacha20_block_xor_neon(state, dst, src);
        bytes -= CHACHA20_BLOCK_SIZE;
        src += CHACHA20_BLOCK_SIZE;
        dst += CHACHA20_BLOCK_SIZE;
        state[12]++;
    }
    if (bytes) {
        memcpy(buf, src, bytes);
        chacha20_block_xor_neon(state, buf, buf);
        memcpy(dst, buf, bytes);
    }
}
#endif

void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t size) {
    uint8_t *keystream_8 = (uint8_t*)ctx->keystream;
    uint8_t *bytes_8 = (uint8_t*)bytes;


    #ifdef HAVE_NEON
    chacha20_doneon(ctx->state, bytes_8, bytes_8, size);
    #else

    for(int i = 0; i < size; i++) {
        uint32_t keystream_position = ctx->position % 64;
        if(keystream_position == 0) {
            chacha20_block_next(ctx);
        }
        bytes_8[i] ^= keystream_8[i % 64];
        ctx->position++;
    }
    #endif
}