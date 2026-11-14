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

	chipvpn_blake2s_concat(hash_key, (const uint8_t*)identifier, sizeof(identifier));
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

void chipvpn_noise_compute_macs(void *packet, size_t size, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub) {
	uint8_t mac1_key[BLAKE2S_HASH_SIZE];
	blake2s_ctx ctx;
	blake2s_init(&ctx, sizeof(mac1_key), NULL, 0);
	blake2s_update(&ctx, (const uint8_t*)"mac1----", 8);
	blake2s_update(&ctx, peer_pub, BLAKE2S_HASH_SIZE);
	blake2s_final(&ctx, mac1_key);

	blake2s_init(&ctx, POLY1305_MAC_SIZE, mac1_key, BLAKE2S_HASH_SIZE);
	blake2s_update(&ctx, (const uint8_t*)packet, size);
	blake2s_final(&ctx, mac1);
	chipvpn_secure_zero(mac2, POLY1305_MAC_SIZE);
}

bool chipvpn_noise_verify_macs(void *packet, size_t size, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub) {
	uint8_t computed_mac1[POLY1305_MAC_SIZE];
	uint8_t computed_mac2[POLY1305_MAC_SIZE];

	chipvpn_noise_compute_macs(packet, size, computed_mac1, computed_mac2, peer_pub);

	return (
		chipvpn_secure_memcmp(mac1, computed_mac1, sizeof(computed_mac1)) == 0 &&
		chipvpn_secure_memcmp(mac2, computed_mac2, sizeof(computed_mac2)) == 0
	);
}

void chipvpn_noise_encrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t size, uint8_t *mac) {
	chipvpn_crypto_chacha20_poly1305_encrypt(cipher_key, data, size, 0, hash_key, BLAKE2S_HASH_SIZE, mac);
	
	uint8_t mixed[CHACHA20_POLY1305_ENC_LEN(size)];
	if(size > 0) {
		memcpy(mixed, data, size);
	}
	memcpy(mixed + size, mac, POLY1305_MAC_SIZE);
	chipvpn_blake2s_concat(hash_key, mixed, sizeof(mixed));
}

bool chipvpn_noise_decrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t size, uint8_t *mac) {
	uint8_t mixed[CHACHA20_POLY1305_ENC_LEN(size)];
	if(size > 0) {
		memcpy(mixed, data, size);
	}
	memcpy(mixed + size, mac, POLY1305_MAC_SIZE);

	if(!chipvpn_crypto_chacha20_poly1305_decrypt(cipher_key, data, size, 0, hash_key, BLAKE2S_HASH_SIZE, mac)) {
		return false;
	}
	chipvpn_blake2s_concat(hash_key, mixed, sizeof(mixed));
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

bool chipvpn_noise_produce_connect(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_packet_auth_t *packet) {
	chipvpn_secure_zero(packet, sizeof(chipvpn_packet_auth_t));

	packet->type = CHIPVPN_PACKET_AUTH;

	peer->handshake.inbound_id = chipvpn_device_generate_index(device);
	if(peer->handshake.inbound_id == 0) {
		return false;
	}

	packet->sender_index = htole32(peer->handshake.inbound_id); 

	chipvpn_noise_init(peer->handshake.chain_key, peer->handshake.hash_key, peer->config.public);

	if(!chipvpn_noise_generate_keypair(peer->handshake.ephemeral_public, peer->handshake.ephemeral_private)) {
		return false;
	}

	memcpy(packet->ephemeral_public, peer->handshake.ephemeral_public, sizeof(peer->handshake.ephemeral_public));

	chipvpn_noise_kdf1(peer->handshake.chain_key, peer->handshake.chain_key, peer->handshake.ephemeral_public, sizeof(peer->handshake.ephemeral_public));
	chipvpn_blake2s_concat(peer->handshake.hash_key, peer->handshake.ephemeral_public, sizeof(peer->handshake.ephemeral_public));

	SECURE32 uint8_t dh_es[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_es, peer->handshake.ephemeral_private, peer->config.public)) {
		return false;
	}

	SECURE32 uint8_t key[CHACHA20_KEY_SIZE];
	chipvpn_noise_kdf2(peer->handshake.chain_key, key, peer->handshake.chain_key, dh_es, sizeof(dh_es));

	memcpy(packet->static_public, device->public, sizeof(device->public));

	chipvpn_noise_encrypt_and_mix(peer->handshake.hash_key, key, packet->static_public, sizeof(packet->static_public), packet->static_public_mac);

	SECURE32 uint8_t dh_ss[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_ss, device->private, peer->config.public)) {
		return false;
	}

	chipvpn_noise_kdf2(peer->handshake.chain_key, key, peer->handshake.chain_key, dh_ss, sizeof(dh_ss));

	chipvpn_tai64n(packet->timestamp);

	chipvpn_noise_encrypt_and_mix(peer->handshake.hash_key, key, packet->timestamp, sizeof(packet->timestamp), packet->timestamp_mac);

	chipvpn_noise_compute_macs(packet, offsetof(chipvpn_packet_auth_t, mac1), packet->mac1, packet->mac2, peer->config.public);

	return true;
}

chipvpn_peer_t *chipvpn_noise_consume_connect(const chipvpn_device_t *device, chipvpn_packet_auth_t *packet) {
	/* init chain_key and hash_key as a working copy to prevent unauthorized changes to the real copy */
	SECURE32 uint8_t chain_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t hash_key[BLAKE2S_HASH_SIZE];

	if(!chipvpn_noise_verify_macs(packet, offsetof(chipvpn_packet_auth_t, mac1), packet->mac1, packet->mac2, device->public)) {
		return NULL;
	}

	chipvpn_noise_init(chain_key, hash_key, device->public);
	chipvpn_noise_kdf1(chain_key, chain_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));
	chipvpn_blake2s_concat(hash_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));

	SECURE32 uint8_t dh_se[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_se, device->private, packet->ephemeral_public)) {
		return NULL;
	}

	SECURE32 uint8_t key[CHACHA20_KEY_SIZE] = {0};

	chipvpn_noise_kdf2(chain_key, key, chain_key, dh_se, sizeof(dh_se));
	
	if(!chipvpn_noise_decrypt_and_mix(hash_key, key, packet->static_public, sizeof(packet->static_public), packet->static_public_mac)) {
		return NULL;
	}

	chipvpn_peer_t *peer = chipvpn_device_lookup_peer_by_pubkey(device, packet->static_public);
	if(!peer) {
		return NULL;
	}

	SECURE32 uint8_t dh_ss[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_ss, device->private, peer->config.public)) {
		return NULL;
	}

	uint8_t key1[BLAKE2S_HASH_SIZE] = {0};
	chipvpn_noise_kdf2(chain_key, key1, chain_key, dh_ss, sizeof(dh_ss));

	if(!chipvpn_noise_decrypt_and_mix(hash_key, key1, packet->timestamp, sizeof(packet->timestamp), packet->timestamp_mac)) {
		return NULL;
	}

	if(memcmp(packet->timestamp, peer->timestamp, sizeof(peer->timestamp)) <= 0) {
		return NULL;
	}

	if(!chipvpn_noise_generate_keypair(peer->handshake.ephemeral_public, peer->handshake.ephemeral_private)) {
		return NULL;
	}

	chipvpn_noise_kdf1(chain_key, chain_key, peer->handshake.ephemeral_public, sizeof(peer->handshake.ephemeral_public));
	chipvpn_blake2s_concat(hash_key, peer->handshake.ephemeral_public, sizeof(peer->handshake.ephemeral_public));

	SECURE32 uint8_t dh_ee[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_ee, peer->handshake.ephemeral_private, packet->ephemeral_public)) {
		return NULL;
	}
	chipvpn_noise_kdf1(chain_key, chain_key, dh_ee, sizeof(dh_ee));

	SECURE32 uint8_t dh_es[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_es, peer->handshake.ephemeral_private, peer->config.public)) {
		return NULL;
	}
	chipvpn_noise_kdf1(chain_key, chain_key, dh_es, sizeof(dh_es));

	peer->handshake.outbound_id = le32toh(packet->sender_index);

	/* copy back timestamp, chain_key and hash_key back to peer after it passed the checks */
	memcpy(peer->timestamp, packet->timestamp, sizeof(packet->timestamp));
	memcpy(peer->handshake.chain_key, chain_key, sizeof(chain_key));
	memcpy(peer->handshake.hash_key, hash_key, sizeof(hash_key));

	return peer;
}

bool chipvpn_noise_produce_reply(chipvpn_peer_t *peer, const chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet) {
	chipvpn_secure_zero(packet, sizeof(chipvpn_packet_auth_reply_t));
	
	packet->type = CHIPVPN_PACKET_AUTH_REPLY;
	packet->receiver_index = htole32(peer->handshake.outbound_id);
	
	peer->handshake.inbound_id = chipvpn_device_generate_index(device);
	if(peer->handshake.inbound_id == 0) {
		return false;
	}

	packet->sender_index = htole32(peer->handshake.inbound_id); 

	SECURE32 uint8_t tau[BLAKE2S_HASH_SIZE] = {0};
	SECURE32 uint8_t key[CHACHA20_KEY_SIZE] = {0};
	uint8_t empty[1] = {0};

	chipvpn_noise_kdf3(peer->handshake.chain_key, tau, key, peer->handshake.chain_key, peer->config.psk, sizeof(peer->config.psk));
	chipvpn_blake2s_concat(peer->handshake.hash_key, tau, sizeof(tau));

	chipvpn_noise_encrypt_and_mix(peer->handshake.hash_key, key, empty, 0, packet->empty_mac);

	memcpy(packet->ephemeral_public, peer->handshake.ephemeral_public, sizeof(peer->handshake.ephemeral_public));

	chipvpn_noise_compute_macs(packet, offsetof(chipvpn_packet_auth_reply_t, mac1), packet->mac1, packet->mac2, peer->config.public);

	return true;
}

chipvpn_peer_t *chipvpn_noise_consume_reply(const chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet) {
	/* init & copy chain_key and hash_key as a working copy to prevent unauthorized changes to the real copy */
	SECURE32 uint8_t chain_key[BLAKE2S_HASH_SIZE];
	SECURE32 uint8_t hash_key[BLAKE2S_HASH_SIZE];

	if(!chipvpn_noise_verify_macs(packet, offsetof(chipvpn_packet_auth_reply_t, mac1), packet->mac1, packet->mac2, device->public)) {
		return NULL;
	}

	chipvpn_peer_t *peer = chipvpn_device_lookup_peer_by_handshake(device, le32toh(packet->receiver_index));
	if(!peer) {
		return NULL;
	}

	memcpy(chain_key, peer->handshake.chain_key, sizeof(peer->handshake.chain_key));
	memcpy(hash_key, peer->handshake.hash_key, sizeof(peer->handshake.hash_key));

	if(le32toh(packet->receiver_index) != peer->handshake.inbound_id) {
		return NULL;
	}

	chipvpn_noise_kdf1(chain_key, chain_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));
	chipvpn_blake2s_concat(hash_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));

	SECURE32 uint8_t dh_ee[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_ee, peer->handshake.ephemeral_private, packet->ephemeral_public)) {
		return NULL;
	}
	chipvpn_noise_kdf1(chain_key, chain_key, dh_ee, sizeof(dh_ee));

	SECURE32 uint8_t dh_se[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_se, device->private, packet->ephemeral_public)) {
		return NULL;
	}
	chipvpn_noise_kdf1(chain_key, chain_key, dh_se, sizeof(dh_se));

	SECURE32 uint8_t tau[BLAKE2S_HASH_SIZE] = {0};
	SECURE32 uint8_t key[CHACHA20_KEY_SIZE] = {0};

	chipvpn_noise_kdf3(chain_key, tau, key, chain_key, peer->config.psk, sizeof(peer->config.psk));
	chipvpn_blake2s_concat(hash_key, tau, sizeof(tau));

	uint8_t dummy[1] = {0};
	if(!chipvpn_noise_decrypt_and_mix(hash_key, key, dummy, 0, packet->empty_mac)) {
		return NULL;
	}

	peer->handshake.outbound_id = le32toh(packet->sender_index);

	/* copy chain_key and hash_key back to peer after it passed the checks */
	memcpy(peer->handshake.chain_key, chain_key, sizeof(chain_key));
	memcpy(peer->handshake.hash_key, hash_key, sizeof(hash_key));

	return peer;
}

bool chipvpn_noise_begin_session(chipvpn_peer_t *peer, bool is_initiator) {
	uint8_t dummy[1] = {0};
	chipvpn_noise_kdf2(
		is_initiator ? peer->next_session.outbound.key : peer->next_session.inbound.key, 
		is_initiator ? peer->next_session.inbound.key  : peer->next_session.outbound.key, 
		peer->handshake.chain_key, 
		dummy, 
		0
	);

	peer->next_session.counter = 0ULL;
	peer->next_session.inbound.id = peer->handshake.inbound_id;
	peer->next_session.outbound.id = peer->handshake.outbound_id;
	chipvpn_bitmap_reset(&peer->next_session.bitmap);

	return true;
}