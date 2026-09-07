#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "dh.h"
#include "util.h"
#include "chacha20.h"
#include "curve25519.h"
#include "hkdf_sha256.h"
#include "hmac_sha256.h"

void chipvpn_dh_half_derive(uint8_t *private_es, uint8_t *public_es, uint8_t *private_ss, uint8_t *public_ss, uint8_t *key) {
	uint8_t dh_combine[2 * CURVE25519_KEY_SIZE];
	int dh_combine_size = CURVE25519_KEY_SIZE;

	uint8_t dh_es[CURVE25519_KEY_SIZE];
	curve25519(
		dh_es, 
		private_es, 
		public_es
	);
	
	memcpy(dh_combine, dh_es, CURVE25519_KEY_SIZE);
	
	if(private_ss && public_ss) {
		uint8_t dh_ss[CURVE25519_KEY_SIZE];
		curve25519(
			dh_ss, 
			private_ss, 
			public_ss
		);

		memcpy(dh_combine + CURVE25519_KEY_SIZE, dh_ss, CURVE25519_KEY_SIZE); // FIX: Copied 'ss', not 'es'
		dh_combine_size = 2 * CURVE25519_KEY_SIZE;
	}

	hkdf_sha256(
		NULL, 
		0, 
		dh_combine,
		dh_combine_size,
		CHIPVPN_FINAL_TAG,
		sizeof(CHIPVPN_FINAL_TAG) - 1,
		key,
		SHA256_HASH_SIZE
	);
}

void chipvpn_dh_sign(uint8_t *private_es, uint8_t *public_es, uint8_t *private_ss, uint8_t *public_ss, uint8_t *payload, int payload_size, uint8_t *aad, int aad_size, uint8_t *sign) {
	uint8_t dh_key[SHA256_HASH_SIZE];
	uint8_t hash_key[SHA256_HASH_SIZE];

	chipvpn_dh_half_derive(private_es, public_es, private_ss, public_ss, dh_key);

	hkdf_sha256(
		NULL, 
		0, 
		dh_key,
		sizeof(dh_key),
		CHIPVPN_HASH_TAG,
		sizeof(CHIPVPN_HASH_TAG) - 1,
		hash_key,
		sizeof(hash_key)
	);

	HMAC_CTX ctx;
	hmac_sha256_init(&ctx, hash_key, sizeof(hash_key));
	hmac_sha256_update(&ctx, payload, payload_size);
	if(aad) {
		hmac_sha256_update(&ctx, aad, aad_size);
	}
	hmac_sha256_final(&ctx, sign, SHA256_HASH_SIZE);

	memset(dh_key, 0, sizeof(dh_key));
	memset(hash_key, 0, sizeof(hash_key));
}

void chipvpn_dh_xcrypt(uint8_t *private_es, uint8_t *public_es, uint8_t *private_ss, uint8_t *public_ss, uint8_t *payload, int payload_size) {
	uint8_t key[SHA256_HASH_SIZE];
	uint8_t crypto_key[CHACHA20_KEY_SIZE];
	uint8_t crypto_nonce[CHACHA20_NONCE_SIZE];

	memset(crypto_key, 0, sizeof(crypto_key));
	memset(crypto_nonce, 0, sizeof(crypto_nonce));

	chipvpn_dh_half_derive(private_es, public_es, private_ss, public_ss, key);

	hkdf_sha256(
		NULL, 
		0, 
		key,
		sizeof(key),
		CHIPVPN_HASH_TAG,
		sizeof(CHIPVPN_HASH_TAG) - 1,
		crypto_key,
		sizeof(crypto_key)
	);

	chacha20_xcrypt(crypto_key, crypto_nonce, payload, payload_size);
}