#ifndef DH_H
#define DH_H

#include <stdint.h>

#define CHIPVPN_FINAL_TAG "#CHIPVPN_FINAL_TAG/1.0"

#define CHIPVPN_HASH_TAG "#CHIPVPN_HASH_TAG/1.0"
#define CHIPVPN_CRYPT_TAG "#CHIPVPN_CRYPT_TAG/1.0"

void chipvpn_dh_half_derive(uint8_t *private_es, uint8_t *public_es, uint8_t *private_ss, uint8_t *public_ss, uint8_t *key);
void chipvpn_dh_full_derive(uint8_t *private_es, uint8_t *public_es, uint8_t *private_ss, uint8_t *public_ss, uint8_t *key);
void chipvpn_dh_sign(uint8_t *private_es, uint8_t *public_es, uint8_t *private_ss, uint8_t *public_ss, uint8_t *payload, int payload_size, uint8_t *aad, int aad_size, uint8_t *sign);
void chipvpn_dh_xcrypt(uint8_t *private_es, uint8_t *public_es, uint8_t *private_ss, uint8_t *public_ss, uint8_t *payload, int payload_size);

#endif