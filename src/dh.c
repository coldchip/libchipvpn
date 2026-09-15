#include <stdint.h>
#include <string.h>
#include "dh.h"
#include "util.h"
#include "chacha20.h"
#include "curve25519.h"
#include "hkdf_sha256.h"
#include "hmac_sha256.h"

void chipvpn_dh_get_public(uint8_t *public, uint8_t *private) {
	uint8_t basepoint[CURVE25519_KEY_SIZE] = {9};
	curve25519(public, private, basepoint);
}

void chipvpn_dh_chain(uint8_t *k1, uint8_t *k2, uint8_t *k3, uint8_t *k4, char *tag, int tag_size, uint8_t *output) {
	uint8_t chaining_key[SHA256_HASH_SIZE];
	uint8_t temp[SHA256_HASH_SIZE];
	uint8_t *keys[] = {k1, k2, k3, k4};
	
	uint8_t *salt = NULL;
	int salt_len = 0;

	chipvpn_secure_zero(output, SHA256_HASH_SIZE);

	for(int i = 0; i < 4; i++) {
		if (keys[i]) {
			hmac_sha256(salt, salt_len, keys[i], CURVE25519_KEY_SIZE, temp, SHA256_HASH_SIZE);
			memcpy(chaining_key, temp, SHA256_HASH_SIZE);

			salt = chaining_key;
			salt_len = SHA256_HASH_SIZE;
		}
	}

	if(salt && tag) {
		hkdf_sha256(
			salt,          salt_len,
			NULL,          0,
			(uint8_t*)tag, tag_size,
			output,        SHA256_HASH_SIZE
		);
	}

	chipvpn_secure_zero(chaining_key, sizeof(chaining_key));
	chipvpn_secure_zero(temp, sizeof(temp));
}

void chipvpn_dh_xcrypt(uint8_t *k1, uint8_t *k2, uint8_t *k3, uint8_t *k4, uint8_t *payload, int payload_size) {
    uint8_t crypto_key[SHA256_HASH_SIZE];
    uint8_t crypto_nonce[CHACHA20_NONCE_SIZE] = {0};

    chipvpn_dh_chain(
        k1, 
        k2, 
        NULL, 
        NULL, 
        CHIPVPN_CRYPT_TAG, 
        sizeof(CHIPVPN_CRYPT_TAG) - 1, 
        crypto_key
    );

    chacha20_xcrypt(crypto_key, crypto_nonce, payload, payload_size);

    chipvpn_secure_zero(crypto_key, sizeof(crypto_key));
}

void chipvpn_dh_sign(uint8_t *k1, uint8_t *k2, uint8_t *k3, uint8_t *k4, uint8_t *payload, int payload_size, uint8_t *output) {
    uint8_t signing_key[SHA256_HASH_SIZE];

    chipvpn_dh_chain(
        k1, 
        k2, 
        NULL, 
        NULL, 
        CHIPVPN_HASH_TAG, 
        sizeof(CHIPVPN_HASH_TAG) - 1, 
        signing_key
    );

    hmac_sha256(
        signing_key, 
        sizeof(signing_key), 
        (uint8_t*)payload, 
        payload_size, 
        output, 
        SHA256_HASH_SIZE
    );

    chipvpn_secure_zero(signing_key, sizeof(signing_key));
}