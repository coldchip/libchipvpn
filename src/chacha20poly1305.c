#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <stdio.h>
#include "chacha20poly1305.h"
#include "chacha20.h"
#include "poly1305.h"
#include "util.h"
#include "log.h"

typedef int (*sodium_init_t)(void);

typedef int (*sodium_encrypt_detached_t)(
    unsigned char *c, unsigned char *mac, unsigned long long *maclen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub,
    const unsigned char *k
);

typedef int (*sodium_decrypt_detached_t)(
    unsigned char *m, unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *mac,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k
);

void *handle = NULL;
sodium_init_t dl_sodium_init = NULL;
sodium_encrypt_detached_t dl_sodium_encrypt_detached = NULL;
sodium_decrypt_detached_t dl_sodium_decrypt_detached = NULL;

void chipvpn_crypto_chacha20_poly1305_init() {
	const char *libs[] = {"libsodium.so", "libsodium.so.23", "libsodium.so.18", "libsodium.so.26.1.0"};

	for(int i = 0; i < 4; i++) {
        handle = dlopen(libs[i], RTLD_LAZY);
        if(handle) break;
    }

    dl_sodium_init = (sodium_init_t)dlsym(handle, "sodium_init");
    dl_sodium_encrypt_detached = (sodium_encrypt_detached_t)dlsym(handle, "crypto_aead_chacha20poly1305_ietf_encrypt_detached");
    dl_sodium_decrypt_detached = (sodium_decrypt_detached_t)dlsym(handle, "crypto_aead_chacha20poly1305_ietf_decrypt_detached");

    if(dl_sodium_init && dl_sodium_encrypt_detached && dl_sodium_decrypt_detached) {
    	if(dl_sodium_init() == 0) {
    		chipvpn_log_append("loaded libsodium\n");
    		chipvpn_log_append("loaded dl_sodium_init @ %p\n", dl_sodium_init);
    		chipvpn_log_append("loaded dl_sodium_encrypt_detached @ %p\n", dl_sodium_encrypt_detached);
    		chipvpn_log_append("loaded dl_sodium_decrypt_detached @ %p\n", dl_sodium_decrypt_detached);
    		return;
    	}
	}

	chipvpn_log_append("libsodium not found, using inbuilt crypto\n");
	chipvpn_crypto_chacha20_poly1305_free();
}

bool chipvpn_crypto_chacha20_poly1305_encrypt(uint8_t *key, uint8_t *data, uint64_t data_size, uint64_t counter, uint8_t *aad, uint64_t aad_size, uint8_t *mac) {
	chacha20_t chacha20_ctx;
	poly1305_context poly1305_ctx;
	uint8_t  nonce[12];
	uint8_t  block0[64];

	// Create 96bit nonce from 64bit counter by copying to 32-96bit region 
	memset(nonce, 0, 4);
	memcpy(nonce + 4, &counter, sizeof(counter));

	if(dl_sodium_encrypt_detached) {
		unsigned long long mac_len;
        int ret = dl_sodium_encrypt_detached(
            data, mac, &mac_len,
            data, data_size,
            aad, aad_size,
            NULL, nonce, key
        );
        return (ret == 0);
	} else {
		// Initialize chacha20 from key and nonce
		chacha20_init_context(&chacha20_ctx, (uint8_t*)key, (uint8_t*)nonce, 0);

		// Generate poly1305 key from key and nonce, internal counter = 0
		memset(block0, 0, sizeof(block0));
		chacha20_xor(&chacha20_ctx, (uint8_t*)block0, sizeof(block0));

		// Encrypt payload, internal counter = 1..2.. and so on
		chacha20_xor(&chacha20_ctx, (uint8_t*)data, data_size);

		// Update poly1305 with data and padding
		poly1305_init(&poly1305_ctx, (unsigned char*)&block0);

		// Update poly1305 with aad
		poly1305_update(&poly1305_ctx, (unsigned char*)aad, aad_size);
		poly1305_update(&poly1305_ctx, (unsigned char*)pad0, (0x10 - aad_size) & 0xf);

		// Update poly1305 with data
		poly1305_update(&poly1305_ctx, (unsigned char*)data, data_size);
		poly1305_update(&poly1305_ctx, (unsigned char*)pad0, (0x10 - data_size) & 0xf);

		// Update poly1305 with size
		poly1305_update(&poly1305_ctx, (unsigned char*)&aad_size, sizeof(aad_size));
		poly1305_update(&poly1305_ctx, (unsigned char*)&data_size, sizeof(data_size));

		// Compute poly1305 and output to mac
		poly1305_finish(&poly1305_ctx, (unsigned char*)mac);

		return true;
	}
}

bool chipvpn_crypto_chacha20_poly1305_decrypt(uint8_t *key, uint8_t *data, uint64_t data_size, uint64_t counter, uint8_t *aad, uint64_t aad_size, uint8_t *mac) {
	chacha20_t chacha20_ctx;
	poly1305_context poly1305_ctx;
	uint8_t  computed_mac[16];
	uint8_t  nonce[12];
	uint8_t  block0[64];

	// Create 96bit nonce from 64bit counter by copying to 32-96bit region 
	memset(nonce, 0, 4);
	memcpy(nonce + 4, &counter, sizeof(counter));

	if(dl_sodium_decrypt_detached) {
		int ret = dl_sodium_decrypt_detached(
            data, NULL,
            data, data_size,
            mac,
            aad, aad_size,
            nonce, key
        );
        return (ret == 0); // 0 = Authenticated and decrypted successfully
	} else {
		// Initialize chacha20 from key and nonce
		chacha20_init_context(&chacha20_ctx, (uint8_t*)key, (uint8_t*)nonce, 0);

		// Generate poly1305 key from key and nonce, internal counter = 0
		memset(block0, 0, sizeof(block0));
		chacha20_xor(&chacha20_ctx, (uint8_t*)block0, sizeof(block0));

		// Update poly1305 with data and padding
		poly1305_init(&poly1305_ctx, (unsigned char*)&block0);

		// Update poly1305 with aad
		poly1305_update(&poly1305_ctx, (unsigned char*)aad, aad_size);
		poly1305_update(&poly1305_ctx, (unsigned char*)pad0, (0x10 - aad_size) & 0xf);

		// Update poly1305 with data
		poly1305_update(&poly1305_ctx, (unsigned char*)data, data_size);
		poly1305_update(&poly1305_ctx, (unsigned char*)pad0, (0x10 - data_size) & 0xf);

		// Update poly1305 with size
		poly1305_update(&poly1305_ctx, (unsigned char*)&aad_size, sizeof(aad_size));
		poly1305_update(&poly1305_ctx, (unsigned char*)&data_size, sizeof(data_size));

		// Compute poly1305 and output to mac
		poly1305_finish(&poly1305_ctx, (unsigned char*)computed_mac);

		// Compare computed mac against input mac
		if(chipvpn_secure_memcmp((uint8_t*)computed_mac, (uint8_t*)mac, 16) != 0) {
			return false;
		}

		// Finally, if mac matches, decrypt payload, internal counter = 1..2.. and so on
		chacha20_xor(&chacha20_ctx, (uint8_t*)data, data_size);

		return true;
	}
}

void chipvpn_crypto_chacha20_poly1305_free() {
	if(handle) {
		dlclose(handle);
		handle = NULL;
	}

	dl_sodium_init = NULL;
    dl_sodium_encrypt_detached = NULL;
    dl_sodium_decrypt_detached = NULL;
}