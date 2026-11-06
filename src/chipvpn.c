#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <stdio.h>
#include "chipvpn.h"
#include "udp.h"
#include "device.h"
#include "ipc.h"
#include "config.h"
#include "packet.h"
#include "address.h"
#include "peer.h"
#include "bitmap.h"
#include "base64.h"
#include "ratelimit.h"
#include "firewall.h"
#include "util.h"
#include "noise.h"
#include "queue.h"

bool chipvpn_init(chipvpn_t *vpn, int tun_fd, int udp_fd, int ipc_fd) {
	vpn->ratelimit = malloc(sizeof(chipvpn_ratelimit_t));
	if(!vpn->ratelimit) {
		return NULL;
	}

	/* clear ratelimit list */
	chipvpn_ratelimit_clear(vpn->ratelimit);

	/* create vpn device */
	if(!chipvpn_device_init(&vpn->device, tun_fd)) {
		return NULL;
	}

	/* create vpn socket */
	if(!chipvpn_udp_init(&vpn->udp, udp_fd)) {
		return NULL;
	}

	/* create control socket */
	if(!chipvpn_ipc_init(&vpn->ipc, ipc_fd)) {
		return NULL;
	}

	return vpn;
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

int chipvpn_service(chipvpn_t *vpn) {
	/* peer lifecycle service */
	chipvpn_device_peer_service(&vpn->device, &vpn->udp);

	uint8_t buffer[QUEUE_ENTRY_SIZE];

	/* ipc */
	while(chipvpn_queue_can_pop(&vpn->ipc.rx_queue) && chipvpn_queue_can_push(&vpn->ipc.tx_queue)) {
		size_t x = chipvpn_queue_pop(&vpn->ipc.rx_queue, buffer, sizeof(buffer) - 1, NULL);
		buffer[x] = '\0';

		chipvpn_config_command(vpn, (char*)buffer);

		chipvpn_queue_push(&vpn->ipc.tx_queue, "OK\n", 3, NULL);
	}

	/* tunnel => socket */
	while(chipvpn_queue_can_pop(&vpn->device.rx_queue) && chipvpn_queue_can_push(&vpn->udp.tx_queue)) {
		size_t r = chipvpn_queue_pop(&vpn->device.rx_queue, buffer, sizeof(buffer), NULL);
		if(r <= 0) {
			continue;
		}

		chipvpn_address_t dst = {0};
		uint8_t version = ((uint8_t *)buffer)[0] >> 4;

		switch(version) {
			case 4: {
				if(r < sizeof(ipv4_hdr_t)) {
					continue;
				}

				ipv4_hdr_t *ipv4_hdr = (ipv4_hdr_t *)buffer;
				dst.type = CHIPVPN_ADDRESS_IPV4;
				dst.ipv4 = ipv4_hdr->dst_addr;
			}
			break;
			case 6: {
				if(r < sizeof(ipv6_hdr_t)) {
					continue;
				}

				ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)buffer;
				dst.type = CHIPVPN_ADDRESS_IPV6;
				memcpy(dst.ipv6, ipv6_hdr->dst_addr, sizeof(ipv6_hdr->dst_addr));
			}
			break;
			default: {
				continue;
			}
		}

		chipvpn_peer_t *peer = chipvpn_device_lookup_peer_by_ip(&vpn->device, &dst);
		if(!peer || !PEER_ACTIVE(peer, chipvpn_get_time())) {
			continue;
		}

		if(!chipvpn_firewall_execute(&peer->firewall_outbound, &dst)) {
			continue;
		}

		peer->session.counter++;

		chipvpn_packet_data_t header = {
			.type    = CHIPVPN_PACKET_DATA,
			.session = htole32(peer->session.outbound.id),
			.counter = htole64(peer->session.counter)
		};

		uint8_t mac[POLY1305_MAC_SIZE];

		bool success = chipvpn_crypto_chacha20_poly1305_encrypt(
			peer->session.outbound.key, 
			buffer, 
			r, 
			peer->session.counter, 
			NULL, 
			0,
			mac
		);

		if(!success) {
			chipvpn_log_append("%p says: unable to encrypt payload\n", peer);
			continue;
		}

		if(peer->ack_state != PEER_ACK_OWE_TX) {
			peer->ack_state = PEER_ACK_OWE_TX;
			peer->last_ack = chipvpn_get_time();
		}

		/* any outbound packet is considered sending a keepalive packet */
		peer->last_transmission = chipvpn_get_time();

		peer->tx += r;

		chipvpn_queue_vector_t vector[] = {
			{ .data = &header, .size = sizeof(header) }, 
			{ .data = buffer, .size = r },
			{ .data = mac, .size = sizeof(mac) }
		};

		chipvpn_queue_push_vector(&vpn->udp.tx_queue, vector, 3, &peer->address);
	}

	/* socket => tunnel */
	while(chipvpn_queue_can_pop(&vpn->udp.rx_queue) && chipvpn_queue_can_push(&vpn->device.tx_queue)) {
		chipvpn_address_t addr;

		size_t r = chipvpn_queue_pop(&vpn->udp.rx_queue, buffer, sizeof(buffer), &addr);
		if(r < sizeof(uint8_t)) {
			continue;
		}

		uint8_t type = buffer[0];
		switch(type) {
			case CHIPVPN_PACKET_AUTH: {
				if(r != sizeof(chipvpn_packet_auth_t)) {
					continue;
				}

				if(!chipvpn_ratelimit_verify(vpn->ratelimit, &addr)) {
					continue;
				}

				chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_noise_consume_connect(&vpn->device, packet);
				if(!peer) {
					if(chipvpn_queue_can_push(&vpn->ipc.tx_queue)) {
						char public_b64[64];

						b64_encode(packet->static_public, sizeof(packet->static_public), (uint8_t*)public_b64);

						chipvpn_ipc_printf(&vpn->ipc, "REJECT %s\n", public_b64);
					}
					chipvpn_log_append("noise handshake failed\n");
					continue;
				}

				chipvpn_peer_recv_connect(peer, &vpn->device, &vpn->udp, packet, &addr);
			}
			break;
			case CHIPVPN_PACKET_AUTH_REPLY: {
				if(r != sizeof(chipvpn_packet_auth_reply_t)) {
					continue;
				}

				if(!chipvpn_ratelimit_verify(vpn->ratelimit, &addr)) {
					continue;
				}

				chipvpn_packet_auth_reply_t *packet = (chipvpn_packet_auth_reply_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_noise_consume_reply(&vpn->device, packet);
				if(!peer) {
					chipvpn_log_append("noise handshake failed\n");
					continue;
				}

				chipvpn_peer_recv_auth_reply(peer, &vpn->device, &vpn->udp, packet, &addr);
			}
			break;
			case CHIPVPN_PACKET_DATA: {
				if(r < sizeof(chipvpn_packet_data_t) + CHACHA20_POLY1305_ENC_LEN(0)) {
					continue;
				}

				chipvpn_packet_data_t *packet      = (chipvpn_packet_data_t*)buffer;
				uint32_t               session_id  = le32toh(packet->session);
				uint64_t               counter     = le64toh(packet->counter);
				uint8_t               *data        = packet->payload;
				size_t                 data_size   = CHACHA20_POLY1305_DEC_LEN(r - sizeof(chipvpn_packet_data_t));
				uint8_t               *mac         = buffer + CHACHA20_POLY1305_DEC_LEN(r);

				chipvpn_peer_session_t *session = NULL;

				chipvpn_peer_t *peer = chipvpn_device_lookup_peer_by_session(&vpn->device, &session, session_id);
				if(!peer || !session || !PEER_ACTIVE(peer, chipvpn_get_time())) {
					continue;
				}

				bool success = chipvpn_crypto_chacha20_poly1305_decrypt(
					session->inbound.key, 
					data, 
					data_size, 
					counter, 
					NULL, 
					0, 
					mac
				);

				if(!success) {
					chipvpn_log_append("%p says: packet has invalid mac\n", peer);
					continue;
				}

				/* must be after decrypt */
				if(!chipvpn_bitmap_validate(&session->bitmap, counter)) {
					chipvpn_log_append("%p says: rejected replayed packet\n", peer);
					continue;
				}

				/* authenticated */
				if(peer->address.ipv4 != addr.ipv4 || peer->address.port != addr.port) {
					chipvpn_log_append("%p says: ip or port changed\n", peer);
					peer->address = addr;
				}

				if(session == &peer->next_session) {
					chipvpn_peer_session_promote(peer);
				}

				if(data_size == 0) {
					chipvpn_peer_recv_keepalive(peer);
					continue;
				}

				if(peer->ack_state != PEER_ACK_OWE_RX) {
					peer->ack_state = PEER_ACK_OWE_RX;
					peer->last_ack = chipvpn_get_time();
				}

				chipvpn_address_t src = {0};
				uint8_t version = ((uint8_t *)data)[0] >> 4;

				switch(version) {
					case 4: {
						if(data_size < sizeof(ipv4_hdr_t)) continue;

						ipv4_hdr_t *ipv4_hdr = (ipv4_hdr_t *)data;
						src.type = CHIPVPN_ADDRESS_IPV4;
						src.ipv4 = ipv4_hdr->src_addr;
					}
					break;
					case 6: {
						if(data_size < sizeof(ipv6_hdr_t)) continue;

						ipv6_hdr_t *ipv6_hdr = (ipv6_hdr_t *)data;
						src.type = CHIPVPN_ADDRESS_IPV6;
						memcpy(src.ipv6, ipv6_hdr->src_addr, sizeof(ipv6_hdr->src_addr));
					}
					break;
					default: {
						continue;
					}
				}

				if(!chipvpn_peer_is_allowed_address(peer, &src)) {
					chipvpn_log_append("%p says: invalid allow ip [%s]\n", peer, chipvpn_address_to_char(&src));
					continue;
				}

				if(!chipvpn_firewall_execute(&peer->firewall_inbound, &src)) {
					continue;
				}

				peer->rx += data_size;

				chipvpn_queue_push(&vpn->device.tx_queue, data, data_size, NULL);
			}
			break;
		}
	}
	return 0;
}

void chipvpn_cleanup(chipvpn_t *vpn) {
	chipvpn_device_cleanup(&vpn->device);
	chipvpn_udp_cleanup(&vpn->udp);
	chipvpn_ipc_cleanup(&vpn->ipc);

	free(vpn->ratelimit);
}