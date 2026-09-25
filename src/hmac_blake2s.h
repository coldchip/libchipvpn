/* Author: Derrick Pallas, Argosy Labs
 * https://github.com/ArgosyLabs/hmac-blake2
 *
 * The contents of this file is free and unencumbered software released into the
 * public domain. For more information, please refer to <http://unlicense.org/>
*/
#ifndef HMAC_BLAKE2S_H
#define HMAC_BLAKE2S_H

#include "blake2s.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void hmac_blake2s(uint8_t *digest, const uint8_t *key, size_t key_len, const uint8_t *text, size_t text_len);

void wireguard_mix_hash(uint8_t *hash, const uint8_t *src, size_t src_len);
void wireguard_kdf1(uint8_t *tau1, const uint8_t *chaining_key, const uint8_t *data, size_t data_len);
void wireguard_kdf2(uint8_t *tau1, uint8_t *tau2, const uint8_t *chaining_key, const uint8_t *data, size_t data_len);
void wireguard_kdf3(uint8_t *tau1, uint8_t *tau2, uint8_t *tau3, const uint8_t *chaining_key, const uint8_t *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif//HMAC_BLAKE2S_H