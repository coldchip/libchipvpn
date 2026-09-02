#include "chacha20.h"

static void chacha20_init_block(chacha20_t *ctx, uint8_t key[], uint8_t nonce[]) {
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

static void chacha20_block_set_counter(chacha20_t *ctx, uint32_t counter) {
    ctx->state[12] = (uint32_t)counter;
}

static void chacha20_block_next(chacha20_t *ctx) {
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

    ctx->state[12] = PLUS(ctx->state[12], 1);
}

void chacha20_init_context(chacha20_t *ctx, uint8_t key[], uint8_t nonce[], uint32_t counter) {
    chacha20_init_block(ctx, key, nonce);
    chacha20_block_set_counter(ctx, counter);

    ctx->position = 0;
}

void chacha20_xor(chacha20_t *ctx, uint8_t *bytes, size_t size) {
    uint8_t *keystream_8 = (uint8_t*)ctx->keystream;
    size_t i = 0;

    size_t offset = ctx->position & 63; 
    if(offset > 0) {
        size_t len = 64 - offset;
        if(len > size) len = size;
        for(size_t j = 0; j < len; j++) {
            bytes[i++] ^= keystream_8[offset + j];
        }
        ctx->position += len;
    }

    while(i + 64 <= size) {
        chacha20_block_next(ctx);
        
        uint32_t *bytes_32 = (uint32_t*)(bytes + i);
        
        for(int k = 0; k < 16; k++) {
            bytes_32[k] ^= ctx->keystream[k];
        }
        
        i += 64;
        ctx->position += 64;
    }

    if(i < size) {
        chacha20_block_next(ctx);
        size_t tail = size - i;
        for(size_t j = 0; j < tail; j++) {
            bytes[i++] ^= keystream_8[j];
        }
        ctx->position += tail;
    }
}