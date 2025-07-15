/*
    hmac_sha256.h
    Originally written by https://github.com/h5p9sl
*/

#ifndef _HMAC_SHA256_H_
#define _HMAC_SHA256_H_

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include "sha256.h"

typedef struct {
    SHA256_CTX hashctx;
    unsigned char key0[64];
    size_t key0_length;
} HMAC_CTX;

void hmac_sha256_init(HMAC_CTX *ctx, const void *v_key, size_t key_length);
void hmac_sha256_update(HMAC_CTX *ctx, const void *message,
                        size_t message_length);
void hmac_sha256_final(HMAC_CTX *ctx, unsigned char *digest,
                       size_t digest_length);

void hmac_sha256(const void *key, size_t key_length, const void *message,
                        size_t message_length, unsigned char *digest,
                        size_t digest_length);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // _HMAC_SHA256_H_
