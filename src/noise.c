#include <string.h>
#include "packet.h"
#include "util.h"
#include "blake2s.h"
#include "hmac_blake2s.h"
#include "chacha20poly1305.h"

void chipvpn_noise_init(uint8_t *chain_key, uint8_t *hash_key, const uint8_t *peer_pub) {
	const char protocol_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
	const char prologue[34]      = "WireGuard v1 zx2c4 Jason@zx2c4.com";

	blake2s(chain_key, BLAKE2S_HASH_SIZE, NULL, 0, protocol_name, sizeof(protocol_name));

	memcpy(hash_key, chain_key, BLAKE2S_HASH_SIZE);

	chipvpn_blake2s_concat(hash_key, (const uint8_t*)prologue, sizeof(prologue));
	chipvpn_blake2s_concat(hash_key, peer_pub, CURVE25519_KEY_SIZE);
}

bool chipvpn_noise_generate_keypair(uint8_t *public, uint8_t *private) {
	chipvpn_secure_random(private, CURVE25519_KEY_SIZE);
	private[0] &= 248;
	private[31] = (private[31] & 127) | 64;

	uint8_t basepoint[CURVE25519_KEY_SIZE] = {9};
	if(!curve25519(public, private, basepoint)) {
		return false;
	}
	return true;
}

void chipvpn_noise_compute_macs(void *packet, size_t auth_len, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub) {
	uint8_t mac1_key[BLAKE2S_HASH_SIZE];
	blake2s_ctx ctx;
	blake2s_init(&ctx, sizeof(mac1_key), NULL, 0);
	blake2s_update(&ctx, (const uint8_t*)"mac1----", 8);
	blake2s_update(&ctx, peer_pub, BLAKE2S_HASH_SIZE);
	blake2s_final(&ctx, mac1_key);

	blake2s_init(&ctx, POLY1305_MAC_SIZE, mac1_key, BLAKE2S_HASH_SIZE);
	blake2s_update(&ctx, (const uint8_t*)packet, auth_len);
	blake2s_final(&ctx, mac1);
	chipvpn_secure_zero(mac2, POLY1305_MAC_SIZE);
}

void chipvpn_noise_encrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t len, uint8_t *mac) {
	chipvpn_crypto_chacha20_poly1305_encrypt(cipher_key, data, len, 0, hash_key, BLAKE2S_HASH_SIZE, mac);
	
	uint8_t mixed[CHACHA20_POLY1305_ENC_LEN(len)];
	if(len > 0) {
		memcpy(mixed, data, len);
	}
	memcpy(mixed + len, mac, POLY1305_MAC_SIZE);
	chipvpn_blake2s_concat(hash_key, mixed, sizeof(mixed));
}

bool chipvpn_noise_decrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t len, uint8_t *mac) {
	uint8_t mixed[CHACHA20_POLY1305_ENC_LEN(len)];
	if(len > 0) {
		memcpy(mixed, data, len);
	}
	memcpy(mixed + len, mac, POLY1305_MAC_SIZE);

	if(!chipvpn_crypto_chacha20_poly1305_decrypt(cipher_key, data, len, 0, hash_key, BLAKE2S_HASH_SIZE, mac)) {
		return false;
	}
	chipvpn_blake2s_concat(hash_key, mixed, sizeof(mixed));
	return true;
}

void chipvpn_blake2s_concat(uint8_t *hash, const uint8_t *src, size_t src_len) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
    blake2s_update(&ctx, hash, BLAKE2S_HASH_SIZE);
    blake2s_update(&ctx, src, src_len);
    blake2s_final(&ctx, hash);
}

void chipvpn_noise_kdf1(uint8_t *tau1, const uint8_t *chaining_key, const uint8_t *data, size_t data_len) {
    uint8_t tau0[BLAKE2S_HASH_SIZE];
    uint8_t output[BLAKE2S_HASH_SIZE + 1];

    // tau0 = Hmac(key, input)
    hmac_blake2s(tau0, chaining_key, BLAKE2S_HASH_SIZE, data, data_len);
    // tau1 := Hmac(tau0, 0x1)
    output[0] = 1;
    hmac_blake2s(output, tau0, BLAKE2S_HASH_SIZE, output, 1);
    memcpy(tau1, output, BLAKE2S_HASH_SIZE);
}

// WireGuard HKDF (Extract and Expand phase yielding 2 keys) using your verified HMAC
void chipvpn_noise_kdf2(uint8_t *tau1, uint8_t *tau2, const uint8_t *chaining_key, const uint8_t *data, size_t data_len) {
    uint8_t tau0[BLAKE2S_HASH_SIZE];
    uint8_t output[BLAKE2S_HASH_SIZE + 1];

    // tau0 = Hmac(key, input)
    hmac_blake2s(tau0, chaining_key, BLAKE2S_HASH_SIZE, data, data_len);
    // tau1 := Hmac(tau0, 0x1)
    output[0] = 1;
    hmac_blake2s(output, tau0, BLAKE2S_HASH_SIZE, output, 1);
    memcpy(tau1, output, BLAKE2S_HASH_SIZE);

    // tau2 := Hmac(tau0,tau1 || 0x2)
    output[BLAKE2S_HASH_SIZE] = 2;
    hmac_blake2s(output, tau0, BLAKE2S_HASH_SIZE, output, BLAKE2S_HASH_SIZE + 1);
    memcpy(tau2, output, BLAKE2S_HASH_SIZE);
}

void chipvpn_noise_kdf3(uint8_t *tau1, uint8_t *tau2, uint8_t *tau3, const uint8_t *chaining_key, const uint8_t *data, size_t data_len) {
    uint8_t tau0[BLAKE2S_HASH_SIZE];
    uint8_t output[BLAKE2S_HASH_SIZE + 1];

    // tau0 = Hmac(key, input)
    hmac_blake2s(tau0, chaining_key, BLAKE2S_HASH_SIZE, data, data_len);
    // tau1 := Hmac(tau0, 0x1)
    output[0] = 1;
    hmac_blake2s(output, tau0, BLAKE2S_HASH_SIZE, output, 1);
    memcpy(tau1, output, BLAKE2S_HASH_SIZE);

    // tau2 := Hmac(tau0,tau1 || 0x2)
    output[BLAKE2S_HASH_SIZE] = 2;
    hmac_blake2s(output, tau0, BLAKE2S_HASH_SIZE, output, BLAKE2S_HASH_SIZE + 1);
    memcpy(tau2, output, BLAKE2S_HASH_SIZE);

    // tau3 := Hmac(tau0,tau1,tau2 || 0x3)
    output[BLAKE2S_HASH_SIZE] = 3;
    hmac_blake2s(output, tau0, BLAKE2S_HASH_SIZE, output, BLAKE2S_HASH_SIZE + 1);
    memcpy(tau3, output, BLAKE2S_HASH_SIZE);
}