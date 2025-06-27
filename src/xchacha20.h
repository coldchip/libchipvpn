#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus 
extern "C" {
#endif

struct chacha20_context
{
  uint32_t keystream32[16];
  size_t position;

  uint8_t key[32];
  uint8_t nonce[12];
  uint64_t counter;

  uint32_t state[16];
};

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nounc[], uint64_t counter);
void chacha20_block_set_nonce(struct chacha20_context *ctx, uint8_t nonce[]);
void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes);
void chacha20_xor2(char *data, int size, char *key, char *nonce, uint32_t counter);

#ifdef __cplusplus 
}
#endif 