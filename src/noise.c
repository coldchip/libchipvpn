#include "peer.h"
#include "packet.h"
#include "util.h"
#include "blake2s.h"
#include "hmac_blake2s.h"

void chipvpn_noise_init(uint8_t *chain_key, uint8_t *hash_key, const uint8_t *peer_pub) {
	const char protocol_name[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
	const char prologue[34]      = "WireGuard v1 zx2c4 Jason@zx2c4.com";

	blake2s(chain_key, BLAKE2S_HASH_SIZE, NULL, 0, protocol_name, sizeof(protocol_name));

	memcpy(hash_key, chain_key, BLAKE2S_HASH_SIZE);

	chipvpn_blake2s_concat(hash_key, (const uint8_t*)prologue, sizeof(prologue));
	chipvpn_blake2s_concat(hash_key, peer_pub, CURVE25519_KEY_SIZE);
}

void chipvpn_noise_compute_macs(void *packet, size_t auth_len, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub) {
	uint8_t mac1_key[BLAKE2S_HASH_SIZE];
	blake2s_ctx ctx;
	blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
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

bool chipvpn_noise_produce_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_packet_auth_t *packet) {
	chipvpn_secure_zero(packet, sizeof(chipvpn_packet_auth_t));

	packet->header.type = CHIPVPN_PACKET_AUTH;

	chipvpn_secure_random((uint8_t*)&peer->next_session.inbound.id, sizeof(peer->next_session.inbound.id));
	packet->sender_index = htole32(peer->next_session.inbound.id); 

	chipvpn_noise_init(peer->handshake.chain_key, peer->handshake.hash_key, peer->config.public);

	chipvpn_secure_random(peer->handshake.ephemeral_private, sizeof(peer->handshake.ephemeral_private));
	peer->handshake.ephemeral_private[0] &= 248;
	peer->handshake.ephemeral_private[31] = (peer->handshake.ephemeral_private[31] & 127) | 64;
	uint8_t basepoint[CURVE25519_KEY_SIZE] = {9};
	if(!curve25519(peer->handshake.ephemeral_public, peer->handshake.ephemeral_private, basepoint)) {
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

	chipvpn_noise_compute_macs(&packet, offsetof(chipvpn_packet_auth_t, mac1), packet->mac1, packet->mac2, peer->config.public);

	return true;
}

chipvpn_peer_t *chipvpn_noise_consume_connect(chipvpn_device_t *device, chipvpn_packet_auth_t *packet) {
	uint8_t chain_key[BLAKE2S_HASH_SIZE];
	uint8_t hash_key[BLAKE2S_HASH_SIZE];

	chipvpn_noise_init(chain_key, hash_key, device->public);
	chipvpn_noise_kdf1(chain_key, chain_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));
	chipvpn_blake2s_concat(hash_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));

	SECURE32 uint8_t dh_se[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_se, device->private, packet->ephemeral_public)) {
		return NULL;
	}

	uint8_t key[CHACHA20_KEY_SIZE] = {0};

	chipvpn_noise_kdf2(chain_key, key, chain_key, dh_se, sizeof(dh_se));
	
	if(!chipvpn_noise_decrypt_and_mix(hash_key, key, packet->static_public, sizeof(packet->static_public), packet->static_public_mac)) {
		return NULL;
	}

	chipvpn_peer_t *peer = chipvpn_peer_get_by_public_key(&device->peers, packet->static_public);
	if(!peer) {
		return NULL;
	}

	memcpy(peer->handshake.chain_key, chain_key, sizeof(chain_key));
	memcpy(peer->handshake.hash_key, hash_key, sizeof(hash_key));

	SECURE32 uint8_t dh_ss[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_ss, device->private, peer->config.public)) {
		return NULL;
	}

	uint8_t key1[BLAKE2S_HASH_SIZE] = {0};
	chipvpn_noise_kdf2(peer->handshake.chain_key, key1, peer->handshake.chain_key, dh_ss, sizeof(dh_ss));

	if(!chipvpn_noise_decrypt_and_mix(peer->handshake.hash_key, key1, packet->timestamp, sizeof(packet->timestamp), packet->timestamp_mac)) {
		return NULL;
	}

	if(memcmp(packet->timestamp, peer->timestamp, sizeof(peer->timestamp)) <= 0) {
		return NULL;
	}

	memcpy(peer->timestamp, packet->timestamp, sizeof(packet->timestamp));

	chipvpn_secure_random(peer->handshake.ephemeral_private, sizeof(peer->handshake.ephemeral_private));
	peer->handshake.ephemeral_private[0] &= 248;
	peer->handshake.ephemeral_private[31] = (peer->handshake.ephemeral_private[31] & 127) | 64;

	// calculate public key
	uint8_t basepoint[CURVE25519_KEY_SIZE] = {9};
	if(!curve25519(peer->handshake.ephemeral_public, peer->handshake.ephemeral_private, basepoint)) {
		return NULL;
	}

	chipvpn_noise_kdf1(peer->handshake.chain_key, peer->handshake.chain_key, peer->handshake.ephemeral_public, sizeof(peer->handshake.ephemeral_public));
	chipvpn_blake2s_concat(peer->handshake.hash_key, peer->handshake.ephemeral_public, sizeof(peer->handshake.ephemeral_public));

	SECURE32 uint8_t dh_ee[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_ee, peer->handshake.ephemeral_private, packet->ephemeral_public)) {
		return NULL;
	}
	chipvpn_noise_kdf1(peer->handshake.chain_key, peer->handshake.chain_key, dh_ee, sizeof(dh_ee));

	SECURE32 uint8_t dh_es[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_es, peer->handshake.ephemeral_private, peer->config.public)) {
		return NULL;
	}
	chipvpn_noise_kdf1(peer->handshake.chain_key, peer->handshake.chain_key, dh_es, sizeof(dh_es));

	return peer;
}

bool chipvpn_noise_produce_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet) {
	chipvpn_secure_zero(packet, sizeof(chipvpn_packet_auth_reply_t));
	packet->header.type = CHIPVPN_PACKET_AUTH_REPLY;
	packet->receiver_index = htole32(peer->next_session.outbound.id);
	chipvpn_secure_random((uint8_t*)&peer->next_session.inbound.id, sizeof(peer->next_session.inbound.id));
	packet->sender_index = htole32(peer->next_session.inbound.id); 

	SECURE32 uint8_t tau[BLAKE2S_HASH_SIZE] = {0};
	SECURE32 uint8_t key[CHACHA20_KEY_SIZE] = {0};
	uint8_t empty[1] = {0};

	chipvpn_noise_kdf3(peer->handshake.chain_key, tau, key, peer->handshake.chain_key, peer->config.psk, sizeof(peer->config.psk));
	chipvpn_blake2s_concat(peer->handshake.hash_key, tau, sizeof(tau));

	chipvpn_noise_encrypt_and_mix(peer->handshake.hash_key, key, empty, 0, packet->empty_mac);

	memcpy(packet->ephemeral_public, peer->handshake.ephemeral_public, sizeof(peer->handshake.ephemeral_public));

	chipvpn_noise_compute_macs(&packet, offsetof(chipvpn_packet_auth_reply_t, mac1), packet->mac1, packet->mac2, peer->config.public);

	return true;
}

chipvpn_peer_t *chipvpn_noise_consume_reply(chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet) {
	chipvpn_peer_t *peer = chipvpn_peer_by_session(&device->peers, NULL, le32toh(packet->receiver_index));
	if(!peer) {
		return NULL;
	}

	if(le32toh(packet->receiver_index) != peer->next_session.inbound.id) {
		return NULL;
	}

	chipvpn_noise_kdf1(peer->handshake.chain_key, peer->handshake.chain_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));
	chipvpn_blake2s_concat(peer->handshake.hash_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));

	SECURE32 uint8_t dh_ee[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_ee, peer->handshake.ephemeral_private, packet->ephemeral_public)) {
		return NULL;
	}
	chipvpn_noise_kdf1(peer->handshake.chain_key, peer->handshake.chain_key, dh_ee, sizeof(dh_ee));

	SECURE32 uint8_t dh_se[CURVE25519_KEY_SIZE];
	if(!curve25519(dh_se, device->private, packet->ephemeral_public)) {
		return NULL;
	}
	chipvpn_noise_kdf1(peer->handshake.chain_key, peer->handshake.chain_key, dh_se, sizeof(dh_se));

	uint8_t tau[BLAKE2S_HASH_SIZE] = {0};
	uint8_t key[CHACHA20_KEY_SIZE] = {0};

	chipvpn_noise_kdf3(peer->handshake.chain_key, tau, key, peer->handshake.chain_key, peer->config.psk, sizeof(peer->config.psk));
	chipvpn_blake2s_concat(peer->handshake.hash_key, tau, sizeof(tau));

	uint8_t dummy[1] = {0};
	if(!chipvpn_noise_decrypt_and_mix(peer->handshake.hash_key, key, dummy, 0, packet->empty_mac)) {
		return NULL;
	}

	return peer;
}