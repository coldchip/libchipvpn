#include <string.h>
#include "hmac_blake2s.h"

void hmac_blake2s(uint8_t *digest, const uint8_t *key, size_t key_len, const uint8_t *text, size_t text_len) {
    // Adapted from appendix example in RFC2104 to use BLAKE2S instead of MD5 - https://tools.ietf.org/html/rfc2104
    blake2s_ctx ctx;
    uint8_t k_ipad[BLAKE2S_BLOCK_SIZE]; // inner padding - key XORd with ipad
    uint8_t k_opad[BLAKE2S_BLOCK_SIZE]; // outer padding - key XORd with opad

    uint8_t tk[BLAKE2S_HASH_SIZE];
    int i;
    // if key is longer than BLAKE2S_BLOCK_SIZE bytes reset it to key=BLAKE2S(key)
    if (key_len > BLAKE2S_BLOCK_SIZE) {
        blake2s_ctx tctx;
        blake2s_init(&tctx, BLAKE2S_HASH_SIZE, NULL, 0);
        blake2s_update(&tctx, key, key_len);
        blake2s_final(&tctx, tk);
        key = tk;
        key_len = BLAKE2S_HASH_SIZE;
    }

    // the HMAC transform looks like:
    // HASH(K XOR opad, HASH(K XOR ipad, text))
    // where K is an n byte key
    // ipad is the byte 0x36 repeated BLAKE2S_BLOCK_SIZE times
    // opad is the byte 0x5c repeated BLAKE2S_BLOCK_SIZE times
    // and text is the data being protected
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    // XOR key with ipad and opad values
    for (i=0; i < BLAKE2S_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    // perform inner HASH
    blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0); // init context for 1st pass
    blake2s_update(&ctx, k_ipad, BLAKE2S_BLOCK_SIZE); // start with inner pad
    blake2s_update(&ctx, text, text_len); // then text of datagram
    blake2s_final(&ctx, digest); // finish up 1st pass

    // perform outer HASH
    blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0); // init context for 2nd pass
    blake2s_update(&ctx, k_opad, BLAKE2S_BLOCK_SIZE); // start with outer pad
    blake2s_update(&ctx, digest, BLAKE2S_HASH_SIZE); // then results of 1st hash
    blake2s_final(&ctx, digest); // finish up 2nd pass
}

// Helper to perform H = Hash(H || data) using the context API
void wireguard_mix_hash(uint8_t *hash, const uint8_t *src, size_t src_len) {
    blake2s_ctx ctx;
    blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
    blake2s_update(&ctx, hash, BLAKE2S_HASH_SIZE);
    blake2s_update(&ctx, src, src_len);
    blake2s_final(&ctx, hash);
}

void wireguard_kdf1(uint8_t *tau1, const uint8_t *chaining_key, const uint8_t *data, size_t data_len) {
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
void wireguard_kdf2(uint8_t *tau1, uint8_t *tau2, const uint8_t *chaining_key, const uint8_t *data, size_t data_len) {
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

void wireguard_kdf3(uint8_t *tau1, uint8_t *tau2, uint8_t *tau3, const uint8_t *chaining_key, const uint8_t *data, size_t data_len) {
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