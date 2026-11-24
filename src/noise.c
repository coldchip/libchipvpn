#include <string.h>
#include <endian.h>
#include "noise.h"
#include "packet.h"
#include "util.h"
#include "blake2s.h"
#include "chacha20poly1305.h"
#include "peer.h"

static const uint8_t protocol[37]   = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const uint8_t identifier[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com";

void chipvpn_noise_init(uint8_t *chain_key, uint8_t *hash_key, const uint8_t *peer_pub) {
	blake2s(chain_key, BLAKE2S_HASH_SIZE, NULL, 0, protocol, sizeof(protocol));
	memcpy(hash_key, chain_key, BLAKE2S_HASH_SIZE);

	chipvpn_blake2s_concat(hash_key, identifier, sizeof(identifier));
	chipvpn_blake2s_concat(hash_key, peer_pub, CURVE25519_KEY_SIZE);
}

bool chipvpn_noise_generate_keypair(uint8_t *public_key, uint8_t *private_key) {
	static const uint8_t basepoint[CURVE25519_KEY_SIZE] = {9};

	if(!chipvpn_secure_random(private_key, CURVE25519_KEY_SIZE)) {
		return false;
	}

	private_key[0] &= 248;
	private_key[31] = (private_key[31] & 127) | 64;

	return curve25519(public_key, private_key, basepoint);
}

void chipvpn_noise_compute_macs(const void *packet, size_t size, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub) {
	static const uint8_t label[8] = "mac1----";
	uint8_t mac1_key[BLAKE2S_HASH_SIZE];
	blake2s_ctx ctx;

	blake2s_init(&ctx, sizeof(mac1_key), NULL, 0);
	blake2s_update(&ctx, label, sizeof(label));
	blake2s_update(&ctx, peer_pub, CURVE25519_KEY_SIZE);
	blake2s_final(&ctx, mac1_key);

	blake2s(mac1, POLY1305_MAC_SIZE, mac1_key, sizeof(mac1_key), (const uint8_t *)packet, size);

	if(mac2) {
		chipvpn_secure_zero(mac2, POLY1305_MAC_SIZE);
	}
}

bool chipvpn_noise_verify_macs(const void *packet, size_t size, const uint8_t *mac1, const uint8_t *mac2, const uint8_t *peer_pub) {
	uint8_t computed_mac1[POLY1305_MAC_SIZE];

	/* TODO: implement mac2 for cookie packet */
	chipvpn_noise_compute_macs(packet, size, computed_mac1, NULL, peer_pub);

	return chipvpn_secure_memcmp(mac1, computed_mac1, sizeof(computed_mac1)) == 0;
}

bool chipvpn_noise_encrypt_and_mix(uint8_t *hash_key, const uint8_t *cipher_key, uint8_t *data, size_t size, uint8_t *mac) {
	blake2s_ctx ctx;

	if(!chipvpn_crypto_chacha20_poly1305_encrypt(cipher_key, data, size, 0, hash_key, BLAKE2S_HASH_SIZE, mac)) {
		return false;
	}

	blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
	blake2s_update(&ctx, hash_key, BLAKE2S_HASH_SIZE);
	if(size > 0) {
		blake2s_update(&ctx, data, size);
	}
	blake2s_update(&ctx, mac, POLY1305_MAC_SIZE);
	blake2s_final(&ctx, hash_key);

	return true;
}

bool chipvpn_noise_decrypt_and_mix(uint8_t *hash_key, const uint8_t *cipher_key, uint8_t *data, size_t size, const uint8_t *mac) {
	blake2s_ctx ctx;

	blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
	blake2s_update(&ctx, hash_key, BLAKE2S_HASH_SIZE);
	if(size > 0) {
		blake2s_update(&ctx, data, size);
	}
	blake2s_update(&ctx, mac, POLY1305_MAC_SIZE);

	if(!chipvpn_crypto_chacha20_poly1305_decrypt(cipher_key, data, size, 0, hash_key, BLAKE2S_HASH_SIZE, mac)) {
		return false;
	}

	blake2s_final(&ctx, hash_key);

	return true;
}

void chipvpn_blake2s_concat(uint8_t *hash, const uint8_t *src, size_t size) {
	blake2s_ctx ctx;
	blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
	blake2s_update(&ctx, hash, BLAKE2S_HASH_SIZE);
	blake2s_update(&ctx, src, size);
	blake2s_final(&ctx, hash);
}

void chipvpn_noise_kdf(uint8_t *t1, uint8_t *t2, uint8_t *t3, const uint8_t *chain_key, const uint8_t *data, size_t size) {
	SECURE32 uint8_t tau0[BLAKE2S_HASH_SIZE];
	uint8_t output[BLAKE2S_HASH_SIZE + 1];

	blake2s_hmac(tau0, chain_key, BLAKE2S_HASH_SIZE, data, size);

	output[0] = 1;
	blake2s_hmac(output, tau0, BLAKE2S_HASH_SIZE, output, 1);
	memcpy(t1, output, BLAKE2S_HASH_SIZE);

	if(t2) {
		output[BLAKE2S_HASH_SIZE] = 2;
		blake2s_hmac(output, tau0, BLAKE2S_HASH_SIZE, output, BLAKE2S_HASH_SIZE + 1);
		memcpy(t2, output, BLAKE2S_HASH_SIZE);
	}

	if(t3) {
		output[BLAKE2S_HASH_SIZE] = 3;
		blake2s_hmac(output, tau0, BLAKE2S_HASH_SIZE, output, BLAKE2S_HASH_SIZE + 1);
		memcpy(t3, output, BLAKE2S_HASH_SIZE);
	}

	chipvpn_secure_zero(tau0, sizeof(tau0));
	chipvpn_secure_zero(output, sizeof(output));
}

int chipvpn_noise_produce_connect(chipvpn_device_t *device, chipvpn_peer_t *peer, chipvpn_packet_auth_t *packet) {
	SECURE32 uint8_t chain_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t hash_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t ephemeral_public[CURVE25519_KEY_SIZE];
	SECURE32 uint8_t ephemeral_private[CURVE25519_KEY_SIZE];
	SECURE32 uint8_t dh[CURVE25519_KEY_SIZE];
	SECURE32 uint8_t key[CHACHA20_KEY_SIZE];

	uint32_t inbound_id = chipvpn_device_generate_index(device);
	if(inbound_id == 0) {
		return CHIPVPN_NOISE_ERR_INDEX;
	}

	chipvpn_secure_zero(packet, sizeof(*packet));
	packet->type         = CHIPVPN_PACKET_AUTH;
	packet->sender_index = htole32(inbound_id);

	chipvpn_noise_init(chain_key, hash_key, peer->config.static_public);

	/* e */
	if(!chipvpn_noise_generate_keypair(ephemeral_public, ephemeral_private)) {
		return CHIPVPN_NOISE_ERR_RNG;
	}
	memcpy(packet->ephemeral_public, ephemeral_public, sizeof(ephemeral_public));
	chipvpn_noise_kdf1(chain_key, chain_key, ephemeral_public, sizeof(ephemeral_public));
	chipvpn_blake2s_concat(hash_key, ephemeral_public, sizeof(ephemeral_public));

	/* es */
	if(!curve25519(dh, ephemeral_private, peer->config.static_public)) {
		return CHIPVPN_NOISE_ERR_DH;
	}
	chipvpn_noise_kdf2(chain_key, key, chain_key, dh, sizeof(dh));

	/* s */
	memcpy(packet->static_public, device->static_public, sizeof(packet->static_public));
	if(!chipvpn_noise_encrypt_and_mix(hash_key, key, packet->static_public, sizeof(packet->static_public), packet->static_public_mac)) {
		return CHIPVPN_NOISE_ERR_AEAD;
	}

	/* ss */
	if(!curve25519(dh, device->static_private, peer->config.static_public)) {
		return CHIPVPN_NOISE_ERR_DH;
	}
	chipvpn_noise_kdf2(chain_key, key, chain_key, dh, sizeof(dh));

	/* timestamp */
	chipvpn_tai64n(packet->timestamp);
	if(!chipvpn_noise_encrypt_and_mix(hash_key, key, packet->timestamp, sizeof(packet->timestamp), packet->timestamp_mac)) {
		return CHIPVPN_NOISE_ERR_AEAD;
	}

	/* mac1 & mac2 */
	chipvpn_noise_compute_macs(packet, offsetof(chipvpn_packet_auth_t, mac1), packet->mac1, packet->mac2, peer->config.static_public);

	/* commit state */
	chipvpn_secure_zero(&peer->handshake, sizeof(peer->handshake));
	peer->handshake.inbound_id = inbound_id;
	memcpy(peer->handshake.chain_key,         chain_key,         sizeof(chain_key));
	memcpy(peer->handshake.hash_key,          hash_key,          sizeof(hash_key));
	memcpy(peer->handshake.ephemeral_private, ephemeral_private, sizeof(ephemeral_private));

	return CHIPVPN_NOISE_OK;
}

int chipvpn_noise_consume_connect(chipvpn_device_t *device, chipvpn_peer_t **peer_out, chipvpn_packet_auth_t *packet, uint8_t *static_public_out) {
	SECURE32 uint8_t chain_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t hash_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t static_public[CURVE25519_KEY_SIZE];
	SECURE32 uint8_t ephemeral_public[CURVE25519_KEY_SIZE];
	SECURE32 uint8_t ephemeral_private[CURVE25519_KEY_SIZE];
	SECURE32 uint8_t dh[CURVE25519_KEY_SIZE];
	SECURE32 uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t timestamp[TAI64N_SIZE];

	if(!chipvpn_noise_verify_macs(packet, offsetof(chipvpn_packet_auth_t, mac1), packet->mac1, packet->mac2, device->static_public)) {
		return CHIPVPN_NOISE_ERR_MAC;
	}

	chipvpn_noise_init(chain_key, hash_key, device->static_public);

	/* e */
	chipvpn_noise_kdf1(chain_key, chain_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));
	chipvpn_blake2s_concat(hash_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));

	/* es */
	if(!curve25519(dh, device->static_private, packet->ephemeral_public)) {
		return CHIPVPN_NOISE_ERR_DH;
	}
	chipvpn_noise_kdf2(chain_key, key, chain_key, dh, sizeof(dh));

	/* s */
	memcpy(static_public, packet->static_public, sizeof(static_public));
	if(!chipvpn_noise_decrypt_and_mix(hash_key, key, static_public, sizeof(static_public), packet->static_public_mac)) {
		return CHIPVPN_NOISE_ERR_AEAD;
	}

	chipvpn_peer_t *peer = chipvpn_device_lookup_peer_by_pubkey(device, static_public);
	if(!peer) {
		if(static_public_out) {
			memcpy(static_public_out, static_public, sizeof(static_public));
		}
		return CHIPVPN_NOISE_ERR_UNKNOWN_PEER;
	}

	/* ss */
	if(!curve25519(dh, device->static_private, peer->config.static_public)) {
		return CHIPVPN_NOISE_ERR_DH;
	}
	chipvpn_noise_kdf2(chain_key, key, chain_key, dh, sizeof(dh));

	/* timestamp & replay check */
	memcpy(timestamp, packet->timestamp, sizeof(timestamp));
	if(!chipvpn_noise_decrypt_and_mix(hash_key, key, timestamp, sizeof(timestamp), packet->timestamp_mac)) {
		return CHIPVPN_NOISE_ERR_AEAD;
	}
	if(memcmp(timestamp, peer->timestamp, sizeof(peer->timestamp)) <= 0) {
		return CHIPVPN_NOISE_ERR_TIMESTAMP;
	}

	/* responder e */
	if(!chipvpn_noise_generate_keypair(ephemeral_public, ephemeral_private)) {
		return CHIPVPN_NOISE_ERR_RNG;
	}
	chipvpn_noise_kdf1(chain_key, chain_key, ephemeral_public, sizeof(ephemeral_public));
	chipvpn_blake2s_concat(hash_key, ephemeral_public, sizeof(ephemeral_public));

	/* ee */
	if(!curve25519(dh, ephemeral_private, packet->ephemeral_public)) {
		return CHIPVPN_NOISE_ERR_DH;
	}
	chipvpn_noise_kdf1(chain_key, chain_key, dh, sizeof(dh));

	/* se */
	if(!curve25519(dh, ephemeral_private, peer->config.static_public)) {
		return CHIPVPN_NOISE_ERR_DH;
	}
	chipvpn_noise_kdf1(chain_key, chain_key, dh, sizeof(dh));

	/* commit state */
	chipvpn_secure_zero(&peer->handshake, sizeof(peer->handshake));
	peer->handshake.outbound_id = le32toh(packet->sender_index);
	memcpy(peer->timestamp,                  timestamp,        sizeof(timestamp));
	memcpy(peer->handshake.chain_key,        chain_key,        sizeof(chain_key));
	memcpy(peer->handshake.hash_key,         hash_key,         sizeof(hash_key));
	memcpy(peer->handshake.ephemeral_public, ephemeral_public, sizeof(ephemeral_public));

	if(peer_out) {
		*peer_out = peer;
	}

	return CHIPVPN_NOISE_OK;
}

int chipvpn_noise_produce_reply(chipvpn_device_t *device, chipvpn_peer_t *peer, chipvpn_packet_auth_reply_t *packet) {
	SECURE32 uint8_t chain_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t hash_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t tau[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t empty[1] = {0};

	memcpy(chain_key, peer->handshake.chain_key, sizeof(chain_key));
	memcpy(hash_key,  peer->handshake.hash_key,  sizeof(hash_key));

	uint32_t inbound_id = chipvpn_device_generate_index(device);
	if(inbound_id == 0) {
		return CHIPVPN_NOISE_ERR_INDEX;
	}

	chipvpn_secure_zero(packet, sizeof(*packet));
	packet->type           = CHIPVPN_PACKET_AUTH_REPLY;
	packet->sender_index   = htole32(inbound_id);
	packet->receiver_index = htole32(peer->handshake.outbound_id);
	memcpy(packet->ephemeral_public, peer->handshake.ephemeral_public, sizeof(packet->ephemeral_public));

	/* psk & empty payload */
	chipvpn_noise_kdf3(chain_key, tau, key, chain_key, peer->config.psk, sizeof(peer->config.psk));
	chipvpn_blake2s_concat(hash_key, tau, sizeof(tau));

	if(!chipvpn_noise_encrypt_and_mix(hash_key, key, empty, 0, packet->empty_mac)) {
		return CHIPVPN_NOISE_ERR_AEAD;
	}

	/* mac1 & mac2 */
	chipvpn_noise_compute_macs(packet, offsetof(chipvpn_packet_auth_reply_t, mac1), packet->mac1, packet->mac2, peer->config.static_public);

	/* commit state */
	peer->handshake.inbound_id = inbound_id;
	memcpy(peer->handshake.chain_key, chain_key, sizeof(chain_key));

	return CHIPVPN_NOISE_OK;
}

int chipvpn_noise_consume_reply(chipvpn_device_t *device, chipvpn_peer_t **peer_out, chipvpn_packet_auth_reply_t *packet) {
	SECURE32 uint8_t chain_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t hash_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t dh[CURVE25519_KEY_SIZE];
	SECURE32 uint8_t tau[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t key[CHACHA20_KEY_SIZE];
	uint8_t empty[1] = {0};

	if(!chipvpn_noise_verify_macs(packet, offsetof(chipvpn_packet_auth_reply_t, mac1), packet->mac1, packet->mac2, device->static_public)) {
		return CHIPVPN_NOISE_ERR_MAC;
	}

	chipvpn_peer_t *peer = chipvpn_device_lookup_peer_by_handshake(device, le32toh(packet->receiver_index));
	if(!peer) {
		return CHIPVPN_NOISE_ERR_UNKNOWN_HANDSHAKE;
	}

	memcpy(chain_key, peer->handshake.chain_key, sizeof(chain_key));
	memcpy(hash_key,  peer->handshake.hash_key,  sizeof(hash_key));

	/* e */
	chipvpn_noise_kdf1(chain_key, chain_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));
	chipvpn_blake2s_concat(hash_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));

	/* ee */
	if(!curve25519(dh, peer->handshake.ephemeral_private, packet->ephemeral_public)) {
		return CHIPVPN_NOISE_ERR_DH;
	}
	chipvpn_noise_kdf1(chain_key, chain_key, dh, sizeof(dh));

	/* se */
	if(!curve25519(dh, device->static_private, packet->ephemeral_public)) {
		return CHIPVPN_NOISE_ERR_DH;
	}
	chipvpn_noise_kdf1(chain_key, chain_key, dh, sizeof(dh));

	/* psk & empty payload */
	chipvpn_noise_kdf3(chain_key, tau, key, chain_key, peer->config.psk, sizeof(peer->config.psk));
	chipvpn_blake2s_concat(hash_key, tau, sizeof(tau));

	if(!chipvpn_noise_decrypt_and_mix(hash_key, key, empty, 0, packet->empty_mac)) {
		return CHIPVPN_NOISE_ERR_AEAD;
	}

	/* commit state */
	peer->handshake.outbound_id = le32toh(packet->sender_index);
	memcpy(peer->handshake.chain_key, chain_key, sizeof(chain_key));

	if(peer_out) {
		*peer_out = peer;
	}

	return CHIPVPN_NOISE_OK;
}

void chipvpn_noise_begin_session(chipvpn_peer_t *peer, bool is_initiator) {
	chipvpn_peer_session_t *next = &peer->next_session;
	uint8_t *tx_key = is_initiator ? next->outbound.key : next->inbound.key;
	uint8_t *rx_key = is_initiator ? next->inbound.key  : next->outbound.key;
	uint8_t empty[1] = {0};

	chipvpn_noise_kdf2(tx_key, rx_key, peer->handshake.chain_key, empty, 0);

	next->last_created = chipvpn_get_tick();
	next->counter      = 0ULL;
	next->inbound.id   = peer->handshake.inbound_id;
	next->outbound.id  = peer->handshake.outbound_id;
	chipvpn_bitmap_reset(&next->bitmap);

	chipvpn_secure_zero(&peer->handshake, sizeof(peer->handshake));
}