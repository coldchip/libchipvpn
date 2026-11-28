#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <stdio.h>
#include "chipvpn.h"
#include "udp.h"
#include "log.h"
#include "device.h"
#include "ipc.h"
#include "config.h"
#include "packet.h"
#include "address.h"
#include "peer.h"
#include "bitmap.h"
#include "base64.h"
#include "firewall.h"
#include "util.h"
#include "noise.h"
#include "queue.h"

bool chipvpn_init(chipvpn_t *vpn, int ipc_fd) {
	/* update cached time */
	chipvpn_update_tick();
	/* create vpn device */
	if(!chipvpn_device_init(&vpn->device)) {
		LOG_ERR("failed to initialize chipvpn tun device\n");
		return false;
	}

	/* create vpn socket */
	if(!chipvpn_udp_init(&vpn->udp)) {
		LOG_ERR("failed to initialize chipvpn udp socket\n");
		return false;
	}

	/* create control socket */
	if(!chipvpn_ipc_init(&vpn->ipc, ipc_fd)) {
		LOG_ERR("failed to initialize chipvpn ipc socket\n");
		return false;
	}

	return true;
}

void chipvpn_poll(chipvpn_t *vpn, uint64_t timeout) {
	struct timeval tv;
	tv.tv_sec  = (time_t)(timeout / 1000);
	tv.tv_usec = (suseconds_t)((timeout % 1000) * 1000);

	int max = 0;

	fd_set rdset, wdset;
	FD_ZERO(&rdset);
	FD_ZERO(&wdset);

	chipvpn_fdset(vpn, &rdset, &wdset, &max);
	
	if(select(max + 1, &rdset, &wdset, NULL, &tv) <= 0) {
		return;
	}

	chipvpn_isset(vpn, &rdset, &wdset);
}

void chipvpn_fdset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset, int *max) {
	int device_max = 0, socket_max = 0, ipc_max = 0;

	chipvpn_device_preselect(&vpn->device, rdset, wdset, &device_max);
	chipvpn_udp_preselect(&vpn->udp,       rdset, wdset, &socket_max);
	chipvpn_ipc_preselect(&vpn->ipc,       rdset, wdset, &ipc_max);

	*max = MAX(device_max, MAX(socket_max, ipc_max));
}

void chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset) {
	chipvpn_device_postselect(&vpn->device, rdset, wdset);
	chipvpn_udp_postselect(&vpn->udp,       rdset, wdset);
	chipvpn_ipc_postselect(&vpn->ipc,       rdset, wdset);
}

void chipvpn_service(chipvpn_t *vpn) {
	/* update cached tick to the current time */
	chipvpn_update_tick();
	/* peer lifecycle service */
	chipvpn_device_peer_service(&vpn->device, &vpn->udp);

	/* buffer for packet processing */
	uint8_t buffer[QUEUE_ENTRY_SIZE];

	/* ipc */
	while(chipvpn_queue_pop_acquire(&vpn->ipc.rx_queue) && chipvpn_queue_push_acquire(&vpn->ipc.tx_queue)) {
		size_t x = chipvpn_queue_pop(&vpn->ipc.rx_queue, buffer, sizeof(buffer) - 1, NULL);
		buffer[x] = '\0';

		chipvpn_config_command(vpn, (char*)buffer);

		chipvpn_queue_push(&vpn->ipc.tx_queue, "OK\n", 3, NULL);
	}

	/* tunnel => socket */
	while(chipvpn_queue_pop_acquire(&vpn->device.rx_queue) && chipvpn_queue_push_acquire(&vpn->udp.tx_queue)) {
		size_t r = chipvpn_queue_pop(&vpn->device.rx_queue, buffer, sizeof(buffer), NULL);
		if(r == 0) {
			continue;
		}

		/* cast packet into chipvpn_address_t based on ipv4 or ipv6 */
		chipvpn_address_t src = {0};
		chipvpn_address_t dst = {0};
		if(!chipvpn_packet_parse_ip(buffer, r, &src, &dst)) {
			continue;
		}

		/* lookup peer by the packet address (authentication) */
		chipvpn_peer_t *peer = chipvpn_device_lookup_peer_by_ip(&vpn->device, &dst);
		if(!peer || !SESSION_ACTIVE(&peer->session)) {
			continue;
		}

		/* if the packet's source is part of peer's outbound firewall (authorisation) */
		if(!chipvpn_firewall_match(&peer->firewall_outbound, &src)) {
			continue;
		}

		/* pad packet to multiple of 16, capped at size of MTU */
		size_t padded = chipvpn_packet_pad_ip(buffer, r, vpn->device.mtu);
		if(padded == 0) {
			continue;
		}

		peer->session.counter++;

		chipvpn_packet_data_t header = {
			.type    = CHIPVPN_PACKET_DATA,
			.session = htole32(peer->session.outbound.id),
			.counter = htole64(peer->session.counter)
		};

		/* attempt to encrypt packet */
		uint8_t mac[POLY1305_MAC_SIZE];

		bool success = chipvpn_crypto_chacha20_poly1305_encrypt(
			peer->session.outbound.key, 
			buffer, 
			padded, 
			peer->session.counter, 
			NULL, 
			0,
			mac
		);

		if(!success) {
			continue;
		}

		/* remote peer owe us a keepalive or a packet */
		PEER_ACK_ARM(peer, PEER_ACK_OWE_TX);

		/* any outbound packet is considered sending a keepalive packet */
		peer->last_transmission = chipvpn_get_tick();

		peer->tx += r;

		chipvpn_queue_vector_t vector[] = {
			{ .data = &header, .size = sizeof(header) }, 
			{ .data = buffer, .size = padded },
			{ .data = mac, .size = sizeof(mac) }
		};

		chipvpn_queue_push_vector(&vpn->udp.tx_queue, vector, 3, &peer->address);
	}

	/* socket => tunnel */
	while(chipvpn_queue_pop_acquire(&vpn->udp.rx_queue) && chipvpn_queue_push_acquire(&vpn->device.tx_queue)) {
		chipvpn_address_t address;

		size_t r = chipvpn_queue_pop(&vpn->udp.rx_queue, buffer, sizeof(buffer), &address);
		if(r < sizeof(uint8_t)) {
			continue;
		}

		uint8_t type = buffer[0];
		switch(type) {
			case CHIPVPN_PACKET_AUTH: {
				if(r != sizeof(chipvpn_packet_auth_t)) {
					continue;
				}

				chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

				chipvpn_peer_t *peer = NULL;
				uint8_t static_public[CURVE25519_KEY_SIZE];

				/* process auth packet */
				int status = chipvpn_noise_consume_connect(&vpn->device, &peer, packet, static_public);
				if(status != CHIPVPN_NOISE_OK) {
					if(status == CHIPVPN_NOISE_ERR_LOOKUP) {
						chipvpn_ipc_send_auth(&vpn->ipc, static_public, &address, packet);
					}
					continue;
				}

				chipvpn_peer_recv_connect(peer, &vpn->device, &vpn->udp, &address);
			}
			break;
			case CHIPVPN_PACKET_AUTH_REPLY: {
				if(r != sizeof(chipvpn_packet_auth_reply_t)) {
					continue;
				}

				chipvpn_packet_auth_reply_t *packet = (chipvpn_packet_auth_reply_t*)buffer;

				chipvpn_peer_t *peer = NULL;

				/* process auth reply packet */
				int status = chipvpn_noise_consume_reply(&vpn->device, &peer, packet);
				if(status != CHIPVPN_NOISE_OK) {
					continue;
				}
				
				chipvpn_peer_recv_auth_reply(peer, &vpn->udp, &address);
			}
			break;
			case CHIPVPN_PACKET_DATA: {
				if(r < sizeof(chipvpn_packet_data_t) + CHACHA20_POLY1305_ENC_LEN(0)) {
					continue;
				}

				chipvpn_packet_data_t *packet       = (chipvpn_packet_data_t*)buffer;
				uint32_t               session_id   = le32toh(packet->session);
				uint64_t               counter      = le64toh(packet->counter);
				uint8_t               *payload      = packet->payload;
				size_t                 payload_size = CHACHA20_POLY1305_DEC_LEN(r - sizeof(chipvpn_packet_data_t));
				uint8_t               *mac          = buffer + CHACHA20_POLY1305_DEC_LEN(r);

				chipvpn_peer_session_t *session = NULL;

				/* lookup peer by its index */
				chipvpn_peer_t *peer = chipvpn_device_lookup_peer_by_session(&vpn->device, &session, session_id);
				if(!peer || !session) {
					continue;
				}

				/* attempt to decrypt packet */
				bool success = chipvpn_crypto_chacha20_poly1305_decrypt(
					session->inbound.key, 
					payload, 
					payload_size, 
					counter, 
					NULL, 
					0, 
					mac
				);

				if(!success) {
					continue;
				}

				/* must be after decrypt */
				if(!chipvpn_bitmap_validate(&session->bitmap, counter)) {
					continue;
				}

				/* update address if it doesn't match */
				if(!chipvpn_address_endpoint_match(&peer->address, &address)) {
					peer->address = address;
				}

				/* promote session if remote peer uses new session */
				if(session == &peer->next_session) {
					chipvpn_peer_session_promote(peer);
				}

				/* keepalive packet, update timers */
				if(payload_size == 0) {
					chipvpn_peer_recv_keepalive(peer);
					continue;
				}

				/* we owe remote a keepalive packet */
				PEER_ACK_ARM(peer, PEER_ACK_OWE_RX);

				/* unpad plaintext to ip total length */
				size_t unpadded = chipvpn_packet_unpad_ip(payload, payload_size);
				if(unpadded == 0) {
					continue;
				}

				/* cast packet into chipvpn_address_t based on ipv4 or ipv6 */
				chipvpn_address_t src = {0};
				chipvpn_address_t dst = {0};
				if(!chipvpn_packet_parse_ip(payload, unpadded, &src, &dst)) {
					continue;
				}

				/* if the packet's source is part of peer's allowedip (authentication) */
				if(!chipvpn_peer_allowip_match(peer, &src)) {
					continue;
				}

				/* if the packet's destination is part of peer's inbound firewall (authorisation) */
				if(!chipvpn_firewall_match(&peer->firewall_inbound, &dst)) {
					continue;
				}

				peer->rx += unpadded;

				chipvpn_queue_push(&vpn->device.tx_queue, payload, unpadded, NULL);
			}
			break;
		}
	}
}

void chipvpn_cleanup(chipvpn_t *vpn) {
	chipvpn_device_cleanup(&vpn->device);
	chipvpn_udp_cleanup(&vpn->udp);
	chipvpn_ipc_cleanup(&vpn->ipc);
}