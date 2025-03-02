/*
	poly1305 implementation using 16 bit * 16 bit = 32 bit multiplication and 32 bit addition
*/

#include <stddef.h>

#if defined(_MSC_VER)
	#define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
	#define POLY1305_NOINLINE __attribute__((noinline))
#else
	#define POLY1305_NOINLINE
#endif

#define poly1305_block_size 16

/* 17 + sizeof(size_t) + 18*sizeof(unsigned short) */
typedef struct poly1305_state_internal_t {
	unsigned char buffer[poly1305_block_size];
	size_t leftover;
	unsigned short r[10];
	unsigned short h[10];
	unsigned short pad[8];
	unsigned char final;
} poly1305_state_internal_t;

typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;

void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);
void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);
void poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const unsigned char key[32]);

int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]);
int poly1305_power_on_self_test(void);