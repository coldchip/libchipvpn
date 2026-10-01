#include <stdint.h>
#include "noise.h"
#include "peer.h"

bool chipvpn_handshake_produce_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_packet_auth_t *packet) {
	chipvpn_secure_zero(packet, sizeof(chipvpn_packet_auth_t));

	packet->header.type = CHIPVPN_PACKET_AUTH;

	chipvpn_secure_random((uint8_t*)&peer->handshake.inbound_id, sizeof(peer->handshake.inbound_id));
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

	chipvpn_noise_compute_macs(&packet, offsetof(chipvpn_packet_auth_t, mac1), packet->mac1, packet->mac2, peer->config.public);

	return true;
}

chipvpn_peer_t *chipvpn_handshake_consume_connect(chipvpn_device_t *device, chipvpn_packet_auth_t *packet) {
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

	if(!chipvpn_noise_generate_keypair(peer->handshake.ephemeral_public, peer->handshake.ephemeral_private)) {
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

	peer->handshake.outbound_id = le32toh(packet->sender_index);

	return peer;
}

bool chipvpn_handshake_produce_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet) {
	chipvpn_secure_zero(packet, sizeof(chipvpn_packet_auth_reply_t));
	packet->header.type = CHIPVPN_PACKET_AUTH_REPLY;
	packet->receiver_index = htole32(peer->handshake.outbound_id);
	chipvpn_secure_random((uint8_t*)&peer->handshake.inbound_id, sizeof(peer->handshake.inbound_id));
	packet->sender_index = htole32(peer->handshake.inbound_id); 

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
chipvpn_peer_t *chipvpn_handshake_consume_reply(chipvpn_device_t *device, chipvpn_packet_auth_reply_t *packet) {
	chipvpn_peer_t *peer = chipvpn_peer_by_handshake(&device->peers, le32toh(packet->receiver_index));
	if(!peer) {
		return NULL;
	}

	if(le32toh(packet->receiver_index) != peer->handshake.inbound_id) {
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

	peer->handshake.outbound_id = le32toh(packet->sender_index);

	return peer;
}

bool chipvpn_handshake_begin_session(chipvpn_peer_t *peer, bool is_initiator) {
	uint8_t dummy[1] = {0};
	chipvpn_noise_kdf2(
		is_initiator ? peer->next_session.outbound.key : peer->next_session.inbound.key, 
		is_initiator ? peer->next_session.inbound.key  : peer->next_session.outbound.key, 
		peer->handshake.chain_key, 
		dummy, 
		0
	);

	peer->next_session.counter = 0llu;
	peer->next_session.inbound.id = peer->handshake.inbound_id;
	peer->next_session.outbound.id = peer->handshake.outbound_id;
	chipvpn_bitmap_reset(&peer->next_session.bitmap);

	return true;
}