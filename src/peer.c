#include "peer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "packet.h"
#include "device.h"
#include "util.h"
#include "sha256.h"
#include "base64.h"
#include "hmac_sha256.h"
#include "hkdf_sha256.h"
#include "curve25519.h"
#include "chacha20poly1305.h"
#include "chacha20.h"
#include "hmac_blake2s.h"
#include "dh.h"
#include "firewall.h"
#include "log.h"

chipvpn_peer_t *chipvpn_peer_create() {
	chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
	if(!peer) {
		return NULL;
	}

	peer->type = PEER_PERMANENT;

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);

	chipvpn_firewall_reset(&peer->config.firewall);

	return peer;
}

void wireguard_build_response_crypto(chipvpn_peer_t *peer, chipvpn_wg_packet_auth_resp_t *reply, const uint8_t *initiator_ephemeral) {
    // 1. Generate & Clamp Ephemeral Keys
    chipvpn_secure_random(peer->ephemeral_private, sizeof(peer->ephemeral_private));
    peer->ephemeral_private[0] &= 248;
    peer->ephemeral_private[31] = (peer->ephemeral_private[31] & 127) | 64;
    chipvpn_dh_get_public(peer->ephemeral_public, peer->ephemeral_private);
    
    // Immediately copy it into the reply packet
    memcpy(reply->ephemeral_public, peer->ephemeral_public, sizeof(peer->ephemeral_public));

    // 2. Mix into Hash & Chain (e)
    wireguard_kdf1(peer->chain_key, peer->chain_key, peer->ephemeral_public, 32);
    wireguard_mix_hash(peer->hash_key, peer->ephemeral_public, 32);

    // 3. Calculate DH(Epriv_r, Epub_i) (ee)
    curve25519(peer->dh_ee, peer->ephemeral_private, initiator_ephemeral);
    wireguard_kdf1(peer->chain_key, peer->chain_key, peer->dh_ee, 32);

    // 4. Calculate DH(Epriv_r, Spub_i) (se)
    curve25519(peer->dh_es, peer->ephemeral_private, peer->config.public);
    wireguard_kdf1(peer->chain_key, peer->chain_key, peer->dh_es, 32);

    // 5. PSK Mixing (psk)
    uint8_t tau[BLAKE2S_HASH_SIZE] = {0};
    uint8_t psk[CHACHA20_KEY_SIZE] = {0};
    uint8_t key1[CHACHA20_KEY_SIZE] = {0};
    wireguard_kdf3(peer->chain_key, tau, key1, peer->chain_key, psk, sizeof(psk));
    wireguard_mix_hash(peer->hash_key, tau, sizeof(tau));

    // 6. Encrypt Empty Payload (msg.empty)
    uint8_t dummy_empty_data[1] = {0};
    chipvpn_crypto_chacha20_poly1305_encrypt(
        key1, dummy_empty_data, 0, 0, peer->hash_key, 32, reply->empty_mac
    );
    wireguard_mix_hash(peer->hash_key, reply->empty_mac, sizeof(reply->empty_mac));
}

int chipvpn_peer_send_wg_reply(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr) {
	chipvpn_wg_packet_auth_resp_t reply;
	memset(&reply, 0, sizeof(reply));
	reply.header.type = 2; // Handshake Response
	reply.receiver_index = htonl(peer->outbound.session); // Send back the client's ID
	chipvpn_secure_random((uint8_t*)&peer->inbound.session, sizeof(peer->inbound.session));
	reply.sender_index = htonl(peer->inbound.session); 


	uint8_t tau[BLAKE2S_HASH_SIZE] = {0};
	uint8_t psk[CHACHA20_KEY_SIZE] = {0};
	uint8_t empty[1] = {0};
	uint8_t key1[CHACHA20_KEY_SIZE] = {0};
	// (Cr, t, k) := Kdf3(Cr, Q)
	wireguard_kdf3(peer->chain_key, tau, key1, peer->chain_key, psk, sizeof(psk));
	// Hr := Hash(Hr | t)
	wireguard_mix_hash(peer->hash_key, tau, sizeof(tau));
	/* msg.empty := AEAD(k, 0, E, Hr) */
	chipvpn_crypto_chacha20_poly1305_encrypt(
	    key1, 
	    empty,
	    0,                  
	    0,                 
	    peer->hash_key,                 
	    32,                
	    reply.empty_mac     
	);
	// Hr := Hash(Hr | msg.empty)
	wireguard_mix_hash(peer->hash_key, reply.empty_mac, sizeof(reply.empty_mac));

	memcpy(reply.ephemeral_public, peer->ephemeral_public, sizeof(peer->ephemeral_public));

	//////////////////////////////////
	uint8_t mac1_key[BLAKE2S_HASH_SIZE];
    blake2s_ctx ctx;

    // 1. Derive the MAC1 key: Hash("mac1----" || Client's Public Key)
    blake2s_init(&ctx, BLAKE2S_HASH_SIZE, NULL, 0);
    blake2s_update(&ctx, (const uint8_t*)"mac1----", 8);
    blake2s_update(&ctx, peer->config.public, CURVE25519_KEY_SIZE);
    blake2s_final(&ctx, mac1_key);

    blake2s_init(&ctx, 16, mac1_key, BLAKE2S_HASH_SIZE); // Output is 16 bytes!
    blake2s_update(&ctx, (const uint8_t*)&reply, 60);
    blake2s_final(&ctx, reply.mac1);

    memset(reply.mac2, 0, 16);

	return chipvpn_socket_write(udp->socket, &reply, sizeof(reply), addr);
}

int chipvpn_peer_recv_wg_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_wg_packet_auth_t *packet, chipvpn_address_t *addr) {
	uint8_t key[BLAKE2S_HASH_SIZE] = {0};

	// (Ci,k) := Kdf2(Ci,DH(Sprivi,Spubr)) (SS)
	wireguard_kdf2(peer->chain_key, key, peer->chain_key, peer->dh_ss, sizeof(peer->dh_ss));

    uint8_t ts_ciphertext_with_mac[28];
    memcpy(ts_ciphertext_with_mac, packet->timestamp, 12);
    memcpy(ts_ciphertext_with_mac + 12, packet->timestamp_mac, 16);

    // Decrypt the timestamp in-place
    bool ts_success = chipvpn_crypto_chacha20_poly1305_decrypt(
        key,                              // The NEW 32-byte key from HKDF
        packet->timestamp,    // The 12-byte timestamp ciphertext
        sizeof(packet->timestamp),                             // Data size is exactly 12 bytes
        0,                              // Nonce is explicitly 0 again
        peer->hash_key,                              // The updated Hash from the previous step
        BLAKE2S_HASH_SIZE,              
        packet->timestamp_mac           // The 16-byte Poly1305 MAC
    );

    if(!ts_success) {
        chipvpn_log_append("WG Handshake Failed: Invalid MAC on Timestamp.\n");
        return 0;
    }

    // Mix the CIPHERTEXT into the hash (Required for the Handshake Response later)
    wireguard_mix_hash(peer->hash_key, ts_ciphertext_with_mac, sizeof(ts_ciphertext_with_mac));

    /* clear and derive keys */
	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	chipvpn_peer_set_state(peer, PEER_CONNECTED);

    peer->outbound.session = ntohl(packet->sender_index);

    // generate curve25519 keys
	chipvpn_secure_random(peer->ephemeral_private, sizeof(peer->ephemeral_private));

	// YOU MUST CLAMP IT HERE!
	peer->ephemeral_private[0] &= 248;
	peer->ephemeral_private[31] = (peer->ephemeral_private[31] & 127) | 64;

	// calculate public key
	chipvpn_dh_get_public(peer->ephemeral_public, peer->ephemeral_private);
	// Cr := Kdf1(Cr,Epubr)
	wireguard_kdf1(peer->chain_key, peer->chain_key, peer->ephemeral_public, sizeof(peer->ephemeral_public));
	// Hr := Hash(Hr || msg.ephemeral)
	wireguard_mix_hash(peer->hash_key, peer->ephemeral_public, sizeof(peer->ephemeral_public));
	// Calculate DH(Eprivi,Epubi)
	curve25519(peer->dh_ee, peer->ephemeral_private, packet->ephemeral_public);
	// Cr := Kdf1(Cr,DH(Eprivi,Epubi))
	wireguard_kdf1(peer->chain_key, peer->chain_key, peer->dh_ee, sizeof(peer->dh_ee));
	// Calculate DH(Eprivi,Spubr)
	curve25519(peer->dh_es, peer->ephemeral_private, peer->config.public);
	// Cr := Kdf1(Cr, DH(Eprivr, Spubi))
	wireguard_kdf1(peer->chain_key, peer->chain_key, peer->dh_es, sizeof(peer->dh_es));
	/* send wireguard peer reply */
	chipvpn_peer_send_wg_reply(peer, device, udp, addr);
    /* derive the key */
    wireguard_kdf2(peer->inbound.key, peer->outbound.key, peer->chain_key, NULL, 0);

	/* reset the bitmap */
	chipvpn_bitmap_reset(&peer->bitmap);

	peer->address = *addr;
	peer->timestamp = 0;
	peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;
	peer->half_auth = false;
	peer->tx = 0llu;
	peer->rx = 0llu;
	peer->last_check = 0llu;
	peer->counter = 0llu;

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->inbound.session, peer->outbound.session);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

    return 0;
}

int chipvpn_peer_send_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_address_t *addr, bool ack) {
	chipvpn_packet_auth_t packet;
	memset(&packet, 0, sizeof(packet));

	packet.header.type = CHIPVPN_PACKET_AUTH;
	packet.version = htonl(CHIPVPN_PROTOCOL_VERSION);
	packet.timestamp = htonll(chipvpn_get_time());
	packet.ack = ack;

	// generate curve25519 keys
	chipvpn_secure_random(peer->ephemeral_private, sizeof(peer->ephemeral_private));

	// calculate public key
	chipvpn_dh_get_public(peer->ephemeral_public, peer->ephemeral_private);

	// compute dh-es
	curve25519(peer->dh_es, peer->ephemeral_private, peer->config.public);

	// copy curve25519 public key to packet
	memcpy(packet.ephemeral_public, peer->ephemeral_public, sizeof(peer->ephemeral_public));

	/* copy keyhash */
	memcpy(packet.static_public, device->public, sizeof(device->public));
	memset(packet.sign, 0, sizeof(packet.sign));

	// sign packet
	chipvpn_dh_sign(
		peer->dh_es,
		peer->dh_ss, 
		NULL,
		NULL,
		(uint8_t*)&packet,
		sizeof(packet),
		packet.sign
	);

	// encrypt static_public
	chipvpn_dh_xcrypt(
		peer->dh_es, 
		NULL,
		NULL,
		NULL,
		packet.static_public, 
		sizeof(packet.static_public)
	);

	peer->half_auth = true;

	return chipvpn_socket_write(udp->socket, &packet, sizeof(packet), addr);
}

int chipvpn_peer_recv_connect(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp, chipvpn_packet_auth_t *packet, chipvpn_address_t *addr) {
	if(ntohl(packet->version) != CHIPVPN_PROTOCOL_VERSION) {
		chipvpn_log_append("invalid protocol version\n");
		return 0;
	}

	uint8_t sign[SHA256_HASH_SIZE];
	uint8_t computed_sign[SHA256_HASH_SIZE];
	memcpy(sign, packet->sign, sizeof(packet->sign));
	memset(packet->sign, 0, sizeof(packet->sign));

	chipvpn_dh_sign(
		peer->dh_se,
		peer->dh_ss,
		NULL,
		NULL,
		(uint8_t*)packet,
		sizeof(chipvpn_packet_auth_t),
		computed_sign
	);

	if(chipvpn_secure_memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
		chipvpn_log_append("invalid sign\n");
		return 0;
	}

	if(ntohll(packet->timestamp) <= peer->timestamp) {
		chipvpn_log_append("packet is replayed or duplicated\n");
		return 0;
	}

	if(
		chipvpn_get_time() - (60 * 1000 * 5) > ntohll(packet->timestamp) ||
		chipvpn_get_time() + (60 * 1000 * 5) < ntohll(packet->timestamp)
	) {
		chipvpn_log_append("invalid time range from peer\n");
		return 0;
	}

	if(packet->ack) {
		chipvpn_log_append("%p says: peer requested auth acknowledgement\n", peer);
		chipvpn_peer_send_connect(peer, device, udp, addr, false);
	}

	if(!peer->half_auth) {
		chipvpn_log_append("peer skipped the first half of the authentication process\n");
		return 0;
	}

	// check randomness distrubution of packet's ephemeral public
	if(!chipvpn_check_key_randomness(packet->ephemeral_public, sizeof(packet->ephemeral_public))) {
		chipvpn_log_append("peer has repeating or highly predictable ephemeral public key\n");
		return 0;
	}

	// reject if peer has same curve25519 public key
	if(chipvpn_secure_memcmp(packet->ephemeral_public, peer->ephemeral_public, sizeof(packet->ephemeral_public)) == 0) {
		chipvpn_log_append("peer has the same curve25519 keys\n");
		return 0;
	}

	/* peer has been authenticated */
	curve25519(peer->dh_ee, peer->ephemeral_private, packet->ephemeral_public);

	/* clear and derive keys */
	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	chipvpn_peer_set_state(peer, PEER_CONNECTED);

	/* reset the bitmap */
	chipvpn_bitmap_reset(&peer->bitmap);

	peer->address = *addr;
	peer->timestamp = ntohll(packet->timestamp);
	peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;
	peer->half_auth = false;
	peer->tx = 0llu;
	peer->rx = 0llu;
	peer->last_check = 0llu;
	peer->counter = 0llu;

	chipvpn_log_append("%p says: hello\n", peer);
	chipvpn_log_append("%p says: session: in [%u] out [%u]\n", peer, peer->inbound.session, peer->outbound.session);
	chipvpn_log_append("%p says: peer connected from [%s:%u]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

	return 0;
}

int chipvpn_peer_send_ping(chipvpn_peer_t *peer, chipvpn_device_t *device, chipvpn_udp_t *udp) {
	peer->counter++;

	if(peer->config.onping) {
		chipvpn_peer_run_command(peer, peer->config.onping);
	}

	chipvpn_packet_data_t header = {
		.header.type = CHIPVPN_PACKET_DATA,
		.session     = htonl(peer->outbound.session),
		.counter     = (peer->counter)
	};

	uint8_t empty[1] = {0};
	uint8_t mac[16];

	if(!chipvpn_peer_encrypt_payload(peer, empty, 0, peer->counter, mac)) {
		chipvpn_log_append("%p says: unable to encrypt payload\n", peer);
		return 0;
	}

	chipvpn_socket_vector_t vector[] = {
		{ .data = &header, .size = sizeof(header) }, 
		{ .data = mac, .size = sizeof(mac) }
	};

	return chipvpn_socket_write_vector(udp->socket, vector, 2, &peer->address);
}

void chipvpn_peer_derive_session(chipvpn_peer_t *peer) {
	// Figure out roles (client or server)
	int role = memcmp(peer->dh_es, peer->dh_se, sizeof(peer->dh_se)) > 0;

	SECURE32 uint8_t dh_shared[SHA256_HASH_SIZE];
	chipvpn_dh_chain(
		peer->dh_ee, 
		peer->dh_ss, 
		role ? peer->dh_es : peer->dh_se, 
		role ? peer->dh_se : peer->dh_es, 
		CHIPVPN_MASTER_TAG,
		sizeof(CHIPVPN_MASTER_TAG) - 1, 
		dh_shared
	);

	// Derive keys
	hkdf_sha256(
		NULL, 
		0, 
		dh_shared,
		sizeof(dh_shared),
		CHIPVPN_DIRECTIONAL_KEY_A,
		sizeof(CHIPVPN_DIRECTIONAL_KEY_A) - 1,
		role ? peer->inbound.key : peer->outbound.key,
		sizeof(peer->inbound.key)
	);

	hkdf_sha256(
		NULL, 
		0, 
		dh_shared,
		sizeof(dh_shared),
		CHIPVPN_DIRECTIONAL_KEY_B,
		sizeof(CHIPVPN_DIRECTIONAL_KEY_B) - 1,
		role ? peer->outbound.key : peer->inbound.key,
		sizeof(peer->outbound.key)
	);

	hkdf_sha256(
		NULL, 
		0, 
		dh_shared,
		sizeof(dh_shared),
		CHIPVPN_SESSION_HASH_A,
		sizeof(CHIPVPN_SESSION_HASH_A) - 1,
		role ? peer->inbound.session_hash : peer->outbound.session_hash,
		sizeof(peer->inbound.session_hash)
	);

	hkdf_sha256(
		NULL, 
		0, 
		dh_shared,
		sizeof(dh_shared),
		CHIPVPN_SESSION_HASH_B,
		sizeof(CHIPVPN_SESSION_HASH_B) - 1,
		role ? peer->outbound.session_hash : peer->inbound.session_hash,
		sizeof(peer->outbound.session_hash)
	);

	chipvpn_secure_zero(dh_shared, sizeof(dh_shared));

	chipvpn_secure_zero(peer->dh_ee, sizeof(peer->dh_ee));
	chipvpn_secure_zero(peer->dh_es, sizeof(peer->dh_es));
	chipvpn_secure_zero(peer->dh_se, sizeof(peer->dh_se));
}

void chipvpn_peer_reset_session(chipvpn_peer_t *peer) {
	chipvpn_secure_zero(&peer->inbound, sizeof(peer->inbound));
	chipvpn_secure_zero(&peer->outbound, sizeof(peer->outbound));

	chipvpn_secure_zero(peer->ephemeral_public, sizeof(peer->ephemeral_public));
	chipvpn_secure_zero(peer->ephemeral_private, sizeof(peer->ephemeral_private));
}

bool chipvpn_peer_set_allow(chipvpn_peer_t *peer, const char *address, uint8_t prefix) {
	if(!chipvpn_address_set_ip(&peer->config.allow, address)) {
		return false;
	}
	peer->config.allow.prefix = prefix;
	return true;
}

bool chipvpn_peer_set_address(chipvpn_peer_t *peer, const char *address, uint16_t port) {
	if(!chipvpn_address_set_ip(&peer->config.address, address)) {
		return false;
	}
	peer->config.address.port = port;
	return true;
}

bool chipvpn_peer_set_public_key(chipvpn_peer_t *peer, chipvpn_device_t *device, const char *key) {
	bool ret = b64_decode((uint8_t*)key, strlen(key), peer->config.public) > 0;
	curve25519(peer->dh_ss, device->private, peer->config.public);
	return ret;
}

bool chipvpn_peer_set_onconnect(chipvpn_peer_t *peer, const char *command) {
	peer->config.onconnect = chipvpn_strdup(command);
	return true;
}

bool chipvpn_peer_set_onping(chipvpn_peer_t *peer, const char *command) {
	peer->config.onping = chipvpn_strdup(command);
	return true;
}

bool chipvpn_peer_set_ondisconnect(chipvpn_peer_t *peer, const char *command) {
	peer->config.ondisconnect = chipvpn_strdup(command);
	return true;
}

chipvpn_peer_t *chipvpn_peer_get_by_public_key(chipvpn_list_t *peers, uint8_t *public) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_secure_memcmp(public, peer->config.public, sizeof(peer->config.public)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_allowip(chipvpn_list_t *peers, chipvpn_address_t *ip) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_address_cidr_match(ip, &peer->config.allow)) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_peer_get_by_inbound_session(chipvpn_list_t *peers, uint32_t session) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(peers); p != chipvpn_list_end(peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		
		if(session == peer->inbound.session) {
			return peer;
		}
	}
	return NULL;
}

void chipvpn_peer_set_state(chipvpn_peer_t *peer, chipvpn_peer_state_e state) {
	if(peer->state != state) {
		peer->state = state;

		switch(state) {
			case PEER_CONNECTED: {
				chipvpn_peer_derive_session(peer);
				if(peer->config.onconnect) {
					chipvpn_peer_run_command(peer, peer->config.onconnect);
				}
			}
			break;
			case PEER_DISCONNECTED: {
				chipvpn_peer_reset_session(peer);
				if(peer->config.ondisconnect) {
					chipvpn_peer_run_command(peer, peer->config.ondisconnect);
				}
			}
			break;
		}
	}
}

void chipvpn_peer_run_command(chipvpn_peer_t *peer, const char *command) {
	char gateway[16];
	char dev[16];
	if(!chipvpn_get_gateway(gateway, dev)) {

	}

	char tx[16];
	char rx[16];
	char keyhash[64 + 1];
	char address[16];
	char port[16];

	if(peer) {
		sprintf(tx, "%lu", peer->tx);
		sprintf(rx, "%lu", peer->rx);

		memset(keyhash, 0, sizeof(keyhash));
		for(int i = 0; i < 32; i++) {
			sprintf(&keyhash[i * 2], "%02x", peer->config.public[i] & 0xff);
		}

		strcpy(address, chipvpn_address_to_char(&peer->address));
		sprintf(port, "%u", peer->address.port);
	}

	char *result1 = chipvpn_str_replace(command, "%gateway%", gateway);
	char *result2 = chipvpn_str_replace(result1, "%gatewaydev%", dev);
	char *result3 = chipvpn_str_replace(result2, "%tx%", tx);
	char *result4 = chipvpn_str_replace(result3, "%rx%", rx);
	char *result5 = chipvpn_str_replace(result4, "%keyhash%", keyhash);
	char *result6 = chipvpn_str_replace(result5, "%paddr%", address);
	char *result7 = chipvpn_str_replace(result6, "%pport%", port);

	if(system(result7) == 0) {
		chipvpn_log_append("%s\n", result7);
	}
	
	free(result1);
	free(result2);
	free(result3);
	free(result4);
	free(result5);
	free(result6);
	free(result7);
}

void chipvpn_peer_service(chipvpn_list_t *peers, chipvpn_device_t *device, chipvpn_udp_t *udp) {
	/* peer lifecycle service */
	uint64_t now = chipvpn_get_time();

	chipvpn_list_node_t *p = chipvpn_list_begin(peers);

	while(p != chipvpn_list_end(peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		p = chipvpn_list_next(p);

		if(now - peer->last_check > CHIPVPN_PEER_PING) {
			peer->last_check = now;

			if(peer->state == PEER_CONNECTED) {
				/* ping peers */
				chipvpn_peer_send_ping(peer, device, udp);

				if(now > peer->timeout) {
					chipvpn_log_append("%p says: peer disconnected\n", peer);
					chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
				}
			} else if(peer->state == PEER_DISCONNECTED) {
				/* attempt to connect to peer */
				if(peer->config.address.ip > 0) {
					chipvpn_log_append("%p says: connecting to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->config.address), peer->config.address.port);
					chipvpn_peer_send_connect(peer, device, udp, &peer->config.address, true);
				}

				if(peer->type == PEER_EPHEMERAL && now > peer->timeout) {
					chipvpn_log_append("%p says: ephemeral peer is removed\n", peer);
					chipvpn_list_remove(&peer->node);
					chipvpn_peer_free(peer);
					continue;
				}
			}
		}
	}
}

bool chipvpn_peer_encrypt_payload(chipvpn_peer_t *peer, uint8_t *data, int size, uint64_t counter, uint8_t *mac) {
	return chipvpn_crypto_chacha20_poly1305_encrypt(
		peer->outbound.key, 
		data, 
		size, 
		counter, 
		NULL, 
		0,
		mac
	);
}

bool chipvpn_peer_decrypt_payload(chipvpn_peer_t *peer, uint8_t *data, int size, uint64_t counter, uint8_t *mac) {
	return chipvpn_crypto_chacha20_poly1305_decrypt(
		peer->inbound.key, 
		data, 
		size, 
		counter, 
		NULL, 
		0, 
		mac
	);
}

void chipvpn_peer_free(chipvpn_peer_t *peer) {
	chipvpn_peer_set_state(peer, PEER_DISCONNECTED);

	if(peer->config.onconnect) {
		free(peer->config.onconnect);
	}

	if(peer->config.onping) {
		free(peer->config.onping);
	}

	if(peer->config.ondisconnect) {
		free(peer->config.ondisconnect);
	}

	chipvpn_secure_zero(peer, sizeof(chipvpn_peer_t));

	free(peer);
}