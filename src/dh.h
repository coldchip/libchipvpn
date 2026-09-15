#ifndef DH_H
#define DH_H

#include <stdint.h>

#define CHIPVPN_FINAL_TAG "#CHIPVPN_FINAL_TAG/1.0"

#define CHIPVPN_HASH_TAG "#CHIPVPN_HASH_TAG/1.0"
#define CHIPVPN_CRYPT_TAG "#CHIPVPN_CRYPT_TAG/1.0"

#define CHIPVPN_MASTER_TAG "#CHIPVPN_MASTER_TAG/1.0"

#define CHIPVPN_DIRECTIONAL_KEY_A "#CHIPVPN_DIRECTIONAL_KEY_A/1.0"
#define CHIPVPN_DIRECTIONAL_KEY_B "#CHIPVPN_DIRECTIONAL_KEY_B/1.0"

#define CHIPVPN_SESSION_HASH_A "#CHIPVPN_SESSION_HASH_A/1.0"
#define CHIPVPN_SESSION_HASH_B "#CHIPVPN_SESSION_HASH_B/1.0"

void chipvpn_dh_get_public(uint8_t *public, uint8_t *private);
void chipvpn_dh_chain(uint8_t *k1, uint8_t *k2, uint8_t *k3, uint8_t *k4, char *tag, int tag_size, uint8_t *output);
void chipvpn_dh_xcrypt(uint8_t *k1, uint8_t *k2, uint8_t *k3, uint8_t *k4, uint8_t *payload, int payload_size);
void chipvpn_dh_sign(uint8_t *k1, uint8_t *k2, uint8_t *k3, uint8_t *k4, uint8_t *payload, int payload_size, uint8_t *output);

#endif