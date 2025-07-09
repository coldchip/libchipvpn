#ifndef CURVE25519_H
#define CURVE25519_H


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CURVE25519_KEY_SIZE 32

void curve25519_donna(unsigned char *output, const unsigned char *a,
                             const unsigned char *b);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* #ifndef CURVE25519_H */
