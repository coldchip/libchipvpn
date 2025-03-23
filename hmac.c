#include <stddef.h>

extern size_t hmac_sha256(const void* key, const size_t keylen, const void* data, void* out, const size_t outlen);

size_t hmac_sha256(const void* key, const size_t keylen, const void* data, void* out, const size_t outlen) {

	printf("hello\n");

}