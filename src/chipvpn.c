#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <endian.h>
#include <stdio.h>
#include "chacha20.h"
#include "chacha20poly1305.h"
#include "curve25519.h"
#include "chipvpn.h"
#include "socket.h"
#include "udp.h"
#include "device.h"
#include "ipc.h"
#include "firewall.h"
#include "config.h"
#include "packet.h"
#include "address.h"
#include "peer.h"
#include "bitmap.h"
#include "blake2s.h"
#include "hmac_blake2s.h"
#include "base64.h"
#include "log.h"
#include "util.h"

chipvpn_t *chipvpn_create(int tun_fd, int udp_fd, int ipc_fd) {
	chipvpn_t *vpn = malloc(sizeof(chipvpn_t));

	setbuf(stdout, 0);

	/* create vpn device */
	chipvpn_device_t *device = chipvpn_device_create(tun_fd);
	if(!device) {
		return NULL;
	}

	/* create vpn socket */
	chipvpn_udp_t *udp = chipvpn_udp_create(udp_fd);
	if(!udp) {
		return NULL;
	}

	/* create control socket */
	chipvpn_ipc_t *ipc = chipvpn_ipc_create(ipc_fd);
	if(!ipc) {
		return NULL;
	}

	vpn->device = device;
	vpn->udp    = udp;
	vpn->ipc    = ipc;

	return vpn;
}

void chipvpn_poll(chipvpn_t *vpn, uint64_t timeout) {
	struct timeval tv;
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

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

	chipvpn_socket_preselect(vpn->device->socket, rdset, wdset, &device_max);
	chipvpn_socket_preselect(vpn->udp->socket, rdset, wdset, &socket_max);
	chipvpn_socket_preselect(vpn->ipc->socket, rdset, wdset, &ipc_max);

	*max = MAX(device_max, MAX(socket_max, ipc_max));
}

void chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset) {
	chipvpn_socket_postselect(vpn->device->socket, rdset, wdset);
	chipvpn_socket_postselect(vpn->udp->socket, rdset, wdset);
	chipvpn_socket_postselect(vpn->ipc->socket, rdset, wdset);
}

int chipvpn_service(chipvpn_t *vpn) {
	/* peer lifecycle service */
	chipvpn_peer_service(&vpn->device->peers, vpn->device, vpn->udp);

	uint8_t buffer[SOCKET_QUEUE_ENTRY_SIZE];

	/* ipc */
	while(chipvpn_socket_can_read(vpn->ipc->socket) && chipvpn_socket_can_write(vpn->ipc->socket)) {
		int x = chipvpn_socket_read(vpn->ipc->socket, buffer, sizeof(buffer), NULL);
		buffer[x] = '\0';

		chipvpn_config_command(vpn, (char*)buffer);

		chipvpn_socket_write(vpn->ipc->socket, "OK\n", 3, NULL);
	}

	/* tunnel => socket */
	while(chipvpn_socket_can_read(vpn->device->socket) && chipvpn_socket_can_write(vpn->udp->socket)) {
		int r = chipvpn_socket_read(vpn->device->socket, buffer, sizeof(buffer), NULL);
		if(r <= 0) {
			continue;
		}

		ip_hdr_t *ip_hdr = (ip_hdr_t*)buffer;

		chipvpn_address_t dst = { .ip = ip_hdr->dst_addr };

		chipvpn_peer_t *peer = chipvpn_peer_get_by_allowip(&vpn->device->peers, &dst);
		if(!peer || peer->state != PEER_CONNECTED) {
			continue;
		}

		if(!chipvpn_firewall_process_ip(&peer->config.firewall, ip_hdr)) {
			continue;
		}

		peer->counter++;

		chipvpn_packet_data_t header = {
			.header.type = CHIPVPN_PACKET_DATA,
			.session     = htole32(peer->outbound.session),
			.counter     = htole64(peer->counter)
		};

		uint8_t mac[16];

		if(!chipvpn_peer_encrypt_payload(peer, buffer, r, peer->counter, mac)) {
			chipvpn_log_append("%p says: unable to encrypt payload\n", peer);
			continue;
		}

		peer->tx += r;

		chipvpn_socket_vector_t vector[] = {
			{ .data = &header, .size = sizeof(header) }, 
			{ .data = buffer, .size = r },
			{ .data = mac, .size = sizeof(mac) }
		};

		chipvpn_socket_write_vector(vpn->udp->socket, vector, 3, &peer->address);
	}

	/* socket => tunnel */
	while(chipvpn_socket_can_read(vpn->udp->socket) && chipvpn_socket_can_write(vpn->device->socket)) {
		chipvpn_address_t addr;

		int r = chipvpn_socket_read(vpn->udp->socket, buffer, sizeof(buffer), &addr);
		if(r < sizeof(chipvpn_packet_header_t)) {
			continue;
		}

		chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
		switch(header->type) {
			case CHIPVPN_PACKET_AUTH: {
				if(r < sizeof(chipvpn_wg_packet_auth_t)) {
					continue;
				}

				chipvpn_wg_packet_auth_t *packet = (chipvpn_wg_packet_auth_t*)buffer;

				uint8_t chain_key[BLAKE2S_HASH_SIZE];
			    uint8_t hash_key[BLAKE2S_HASH_SIZE];

			    chipvpn_init_noise(chain_key, hash_key, vpn->device->public);
				chipvpn_blake2s_kdf1(chain_key, chain_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));
				chipvpn_blake2s_concat(hash_key, packet->ephemeral_public, sizeof(packet->ephemeral_public));

				SECURE32 uint8_t dh_se[CURVE25519_KEY_SIZE];
				curve25519(
				    dh_se, 
				    vpn->device->private, 
				    packet->ephemeral_public
				);

				uint8_t enc_static[CURVE25519_KEY_SIZE + 16] = {0};
				memcpy(enc_static, packet->static_public, sizeof(packet->static_public));
				memcpy(enc_static + sizeof(packet->static_public), packet->static_public_mac, sizeof(packet->static_public_mac));

				uint8_t key[CHACHA20_KEY_SIZE] = {0};

				chipvpn_blake2s_kdf2(chain_key, key, chain_key, dh_se, sizeof(dh_se)); // Updates chaining key C, outputs cipher key K
				
			    if(!chipvpn_decrypt_and_mix(hash_key, key, packet->static_public, sizeof(packet->static_public), packet->static_public_mac)) {
			    	chipvpn_log_append("unable to decrypt\n");
			    	continue;
			    }

				chipvpn_peer_t *peer = chipvpn_peer_get_by_public_key(&vpn->device->peers, packet->static_public);
				if(!peer) {
					if(chipvpn_socket_can_write(vpn->ipc->socket)) {
						char public_b64[64];
						char bufstr[512];

						b64_encode(packet->static_public, sizeof(packet->static_public), (uint8_t*)public_b64);

						sprintf(bufstr, "REJECT %s\n", public_b64);
						chipvpn_socket_write(vpn->ipc->socket, bufstr, strlen(bufstr), NULL);
					}
					chipvpn_log_append("public key not found\n");
					continue;
				}

				memcpy(peer->dh_se, dh_se, sizeof(dh_se));
				memcpy(peer->chain_key, chain_key, sizeof(chain_key));
				memcpy(peer->hash_key, hash_key, sizeof(hash_key));

				chipvpn_peer_recv_wg_connect(peer, vpn->device, vpn->udp, packet, &addr);
			}
			break;
			case CHIPVPN_PACKET_AUTH_REPLY: {
				if(r < sizeof(chipvpn_wg_packet_auth_resp_t)) {
					continue;
				}

				chipvpn_wg_packet_auth_resp_t *packet  = (chipvpn_wg_packet_auth_resp_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_inbound_session(&vpn->device->peers, le32toh(packet->receiver_index));
				if(!peer) {
					continue;
				}

				chipvpn_peer_recv_wg_reply(peer, vpn->device, vpn->udp, packet, &addr);
			}
			break;
			case CHIPVPN_PACKET_DATA: {
				if(r < sizeof(chipvpn_packet_data_t)) {
					continue;
				}

				chipvpn_packet_data_t *packet      = (chipvpn_packet_data_t*)buffer;
				uint32_t               session     = le32toh(packet->session);
				uint64_t               counter     = le64toh(packet->counter);
				uint8_t               *data        = packet->payload;
				int                    data_size   = r - sizeof(chipvpn_packet_data_t) - 16;
				uint8_t               *mac         = buffer + (r - 16);

				chipvpn_peer_t *peer = chipvpn_peer_get_by_inbound_session(&vpn->device->peers, session);
				if(!peer || peer->state != PEER_CONNECTED) {
					continue;
				}

				if(data_size < 0) {
					chipvpn_log_append("%p says: size of packet is negative\n", peer);
					continue;
				}

				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					chipvpn_log_append("%p says: invalid src ip or src port\n", peer);
					continue;
				}

				if(!chipvpn_peer_decrypt_payload(peer, data, data_size, counter, mac)) {
					chipvpn_log_append("%p says: packet has invalid mac\n", peer);
					continue;
				}

				/* must be after decrypt */
				if(!chipvpn_bitmap_validate(&peer->bitmap, counter)) {
					chipvpn_log_append("%p says: rejected replayed packet\n", peer);
					continue;
				}

				/* keep peer alive */
				peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;

				if(data_size == 0) {
					char tx[128];
					char rx[128];
					strcpy(tx, chipvpn_format_bytes(peer->tx));
					strcpy(rx, chipvpn_format_bytes(peer->rx));

					chipvpn_log_append("%p says: received ping packet\n", peer);
					chipvpn_log_append("%p says: tx: [%s] rx: [%s]\n", peer, tx, rx);
					continue;
				}

				ip_hdr_t *ip_hdr = (ip_hdr_t*)data;

				if(!chipvpn_firewall_process_ip(&peer->config.firewall, ip_hdr)) {
					continue;
				}

				chipvpn_address_t src = { .ip = ip_hdr->src_addr };

				if(chipvpn_peer_get_by_allowip(&vpn->device->peers, &src) != peer) {
					chipvpn_log_append("%p says: invalid allow ip [%s]\n", peer, chipvpn_address_to_char(&src));
					continue;
				}

				peer->rx += data_size;
				chipvpn_socket_write(vpn->device->socket, data, data_size, NULL);
			}
			break;
		}
	}
	return 0;
}

void chipvpn_cleanup(chipvpn_t *vpn) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&vpn->device->peers); p != chipvpn_list_end(&vpn->device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	}

	chipvpn_device_free(vpn->device);
	chipvpn_udp_free(vpn->udp);
	chipvpn_ipc_free(vpn->ipc);

	free(vpn);
}