#include "sha256.h"
#include "hmac_sha256.h"
#include <stdlib.h>

enum {
	/* This is the 256-bit output of the SHA-256 function */
	DIGEST_SIZE = 32,
	/* This is the 512-bit internal blocksize within the SHA-256 function */
	BLOCK_SIZE = 64,
};

void hmac_sha256_init(HMAC_CTX *ctx, const void *v_key, size_t key_length) {
	const unsigned char *key = (const unsigned char *)v_key;
	size_t i;
	unsigned char ipad[BLOCK_SIZE];

	/*
	 * FIPS 198-1 - Step 2
	 * If the length of K > B: hash K to obtain an L byte string,
	 * then append (B-L) zeros to create a B-byte string K0
	 */
	if (key_length > BLOCK_SIZE) {
		SHA256_CTX hashctx;
		sha256_init(&hashctx);
		sha256_update(&hashctx, key, key_length);
		sha256_final(&hashctx, ctx->key0);
		ctx->key0_length = DIGEST_SIZE;
	} else {
		for (i = 0; i < key_length; i++)
			ctx->key0[i] = key[i];
		ctx->key0_length = key_length;
	}

	/*
	 * FIPS 198-1 - Step 3
	 * If the length of K < B: append zeros to the end of K to create a
	 * B-byte string K0 */
	for (i = ctx->key0_length; i < BLOCK_SIZE; i++)
		ctx->key0[i] = 0;

	/* FIPS 198-1 - Step 4
	 * Exclusive-Or K0 with ipad to produce a B-byte string: K0 ⊕ ipad. */
	for (i = 0; i < BLOCK_SIZE; i++)
		ipad[i] = ctx->key0[i] ^ 0x36;

	/* FIPS 198-1 - Step 5a
	 * "Append the stream of data 'text' to the string resulting from step 4:
	 * (K0 ⊕ ipad) || text."
	 *
	 * This means we start doing the underlying hash with 'ipad', before
	 * continuing later with 'text'. */
	sha256_init(&ctx->hashctx);
	sha256_update(&ctx->hashctx, ipad, BLOCK_SIZE);
}

void hmac_sha256_update(HMAC_CTX *ctx, const void *message,
						size_t message_length) {
	/* FIPS 198-1 - Step 5b
	 * "Append the stream of data 'text' to the string resulting from step 4:
	 * (K0 ⊕ ipad) || text."
	 *
	 * We already started hashing 'ipad' in the _init() function, so we
	 * just continue here hashing 'text' (aka. 'message'). */
	sha256_update(&ctx->hashctx, message, message_length);
}

void hmac_sha256_final(HMAC_CTX *ctx, unsigned char *digest,
					   size_t digest_length) {
	size_t i;
	unsigned char opad[BLOCK_SIZE];

	if (digest_length < DIGEST_SIZE)
		abort();

	/* FIPS 198-1 - Step 6
	 * "Step 6 Apply H to the stream generated in step 5:
	 * H((K0 ⊕ ipad) || text)."
	 *
	 * For this code, this step maps with finalizing the hash after doing
	 * multiple updates.
	 */
	sha256_final(&ctx->hashctx, digest);

	/* FIPS 198-1 - Step 7
	 * "Exclusive-Or K0 with opad: K0 ⊕ opad."
	 */
	for (i = 0; i < BLOCK_SIZE; i++)
		opad[i] = ctx->key0[i] ^ 0x5C;

	/* FIPS 198-1 - Step 8 and Step 9
	 * Step 8 - Append the result from step 6 to step 7:
	 *  (K0 ⊕ opad) || H((K0 ⊕ ipad) || text).
	 * Step 9 - Apply H to the result from step 8:
	 *  H((K0 ⊕ opad )|| H((K0 ⊕ ipad) || text)). */
	sha256_init(&ctx->hashctx);
	sha256_update(&ctx->hashctx, opad, BLOCK_SIZE);
	sha256_update(&ctx->hashctx, digest, DIGEST_SIZE);
	sha256_final(&ctx->hashctx, digest);
}

void hmac_sha256(const void *key, size_t key_length, const void *message,
						size_t message_length, unsigned char *digest,
						size_t digest_length) {
	HMAC_CTX ctx;

	hmac_sha256_init(&ctx, key, key_length);
	hmac_sha256_update(&ctx, message, message_length);
	hmac_sha256_final(&ctx, digest, digest_length);
}