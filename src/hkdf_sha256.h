#ifndef HKDF_SHA256_HKDF_H
#define HKDF_SHA256_HKDF_H

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>

int hkdf_sha256(const void *salt, size_t salt_length, const void *ikm,
                size_t ikm_length, const void *info, size_t info_len,
                unsigned char *okm, size_t okm_len);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif