#ifndef CURVE25519_H
#define CURVE25519_H


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdint.h>

#ifdef _MSC_VER
#define inline __inline
#endif

typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

#define CURVE25519_KEY_SIZE 32

int curve25519(u8 *mypublic, const u8 *secret, const u8 *basepoint);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* #ifndef CURVE25519_H */
