#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "chacha20poly1305.h"
#include "chipvpn.h"
#include "socket.h"
#include "packet.h"
#include "address.h"
#include "peer.h"
#include "bitmap.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "log.h"
#include "util.h"

chipvpn_t *chipvpn_create(chipvpn_config_t *config, int tun_fd) {
	chipvpn_t *vpn = malloc(sizeof(chipvpn_t));

	setbuf(stdout, 0);

	/* create vpn device */
	chipvpn_device_t *device = chipvpn_device_create(tun_fd);
	if(!device) {
		return NULL;
	}

	/* create vpn socket */
	chipvpn_socket_t *socket = chipvpn_socket_create();
	if(!socket) {
		return NULL;
	}

	if(tun_fd < 0) {
		if(!chipvpn_device_set_name(device, config->name)) {
			return NULL;
		}

		if(!chipvpn_device_set_address(device, &config->network)) {
			return NULL;
		}

		if(!chipvpn_device_set_mtu(device, config->mtu)) {
			return NULL;
		}
		
		if(!chipvpn_device_set_enabled(device)) {
			return NULL;
		}
	}

	if(config->sendbuf > 0 && !chipvpn_socket_set_sendbuf(socket, config->sendbuf)) {
		return NULL;
	}

	if(config->recvbuf > 0 && !chipvpn_socket_set_recvbuf(socket, config->recvbuf)) {
		return NULL;
	}

	if(config->has_bind) {
		chipvpn_log_append("device has bind set\n");
		if(!chipvpn_socket_bind(socket, &config->bind)) {
			return NULL;
		}
	}

	vpn->device = device;
	vpn->socket = socket;

	return vpn;
}

void chipvpn_poll(chipvpn_t *vpn, uint64_t timeout) {
	fd_set rdset, wdset;
	FD_ZERO(&rdset);
	FD_ZERO(&wdset);

	struct timeval tv;
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

	int max = 0;

	chipvpn_fdset(vpn, &rdset, &wdset, &max);
	
	if(select(max + 1, &rdset, &wdset, NULL, &tv) > 0) {
		chipvpn_isset(vpn, &rdset, &wdset);
	}
}

void chipvpn_fdset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset, int *max) {
	int device_max = 0, socket_max = 0;

	chipvpn_device_preselect(vpn->device, rdset, wdset, &device_max);
	chipvpn_socket_preselect(vpn->socket, rdset, wdset, &socket_max);

	*max = MAX(device_max, socket_max);
}

void chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset) {
	chipvpn_device_postselect(vpn->device, rdset, wdset);
	chipvpn_socket_postselect(vpn->socket, rdset, wdset);
}

int chipvpn_service(chipvpn_t *vpn) {
	/* peer lifecycle service */
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&vpn->device->peers); p != chipvpn_list_end(&vpn->device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		if(chipvpn_get_time() - peer->last_check > CHIPVPN_PEER_PING) {
			peer->last_check = chipvpn_get_time();

			/* disconnect unpinged peer and check against connect/disconnect timeout timers */
			if(peer->state != PEER_DISCONNECTED && chipvpn_get_time() > peer->timeout) {
				chipvpn_log_append("%p says: peer disconnected\n", peer);
				chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
			}

			/* attempt to connect to peer */
			if(peer->state == PEER_DISCONNECTED && peer->config.connect) {
				chipvpn_log_append("%p says: connecting to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->config.address), peer->config.address.port);
				chipvpn_peer_send_connect(vpn, peer, &peer->config.address);
			}

			/* ping peers */
			if(peer->state == PEER_CONNECTED) {
				chipvpn_peer_send_ping(vpn, peer);
			}
		}
	}

	/* tunnel => socket */
	if(chipvpn_device_can_read(vpn->device) && chipvpn_socket_can_write(vpn->socket)) {
		uint8_t buffer[SOCKET_QUEUE_ENTRY_SIZE];

		chipvpn_packet_data_t *header = (chipvpn_packet_data_t*)buffer;
		uint8_t               *data   = buffer + sizeof(chipvpn_packet_data_t);

		int r = chipvpn_device_read(vpn->device, data, sizeof(buffer) - sizeof(chipvpn_packet_data_t));
		if(r <= 0) {
			return 0;
		}

		ip_hdr_t *ip_hdr = (ip_hdr_t*)data;
		if(ip_hdr->version != 4) {
			return 0;
		}

		chipvpn_address_t dst = {
			.ip = ip_hdr->dst_addr
		};

		chipvpn_peer_t *peer = chipvpn_peer_get_by_allowip(&vpn->device->peers, &dst);
		if(!peer || peer->state != PEER_CONNECTED) {
			return 0;
		}

		header->header.type = CHIPVPN_PACKET_DATA;
		header->session     = htonl(peer->outbound_session);
		header->counter     = htonll(peer->counter);

		if(!chipvpn_crypto_chacha20_poly1305_encrypt(&peer->crypto, data, r, peer->counter++, header->mac)) {
			chipvpn_log_append("%p says: unable to encrypt payload\n", peer);
			return 0;
		}

		peer->tx += r;
		chipvpn_socket_write(vpn->socket, buffer, sizeof(chipvpn_packet_data_t) + r, &peer->address);
	}

	/* socket => tunnel */
	if(chipvpn_socket_can_read(vpn->socket) && chipvpn_device_can_write(vpn->device)) {
		uint8_t buffer[SOCKET_QUEUE_ENTRY_SIZE];
		chipvpn_address_t addr;

		int r = chipvpn_socket_read(vpn->socket, buffer, sizeof(buffer), &addr);
		if(r < sizeof(chipvpn_packet_header_t)) {
			return 0;
		}

		chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
		switch(header->type) {
			case CHIPVPN_PACKET_AUTH: {
				if(r < sizeof(chipvpn_packet_auth_t)) {
					return 0;
				}

				chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(&vpn->device->peers, packet->keyhash);
				if(!peer) {
					return 0;
				}

				return chipvpn_peer_recv_connect(vpn, peer, packet, &addr);
			}
			break;
			case CHIPVPN_PACKET_DATA: {
				if(r < sizeof(chipvpn_packet_data_t)) {
					return 0;
				}

				chipvpn_packet_data_t *packet = (chipvpn_packet_data_t*)buffer;
				uint8_t               *data   = buffer + sizeof(chipvpn_packet_data_t);

				chipvpn_peer_t *peer = chipvpn_peer_get_by_session(&vpn->device->peers, ntohl(packet->session));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}

				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					chipvpn_log_append("%p says: invalid src ip or src port\n", peer);
					return 0;
				}

				if(!chipvpn_crypto_chacha20_poly1305_decrypt(&peer->crypto, data, r - sizeof(chipvpn_packet_data_t), ntohll(packet->counter), packet->mac)) {
					chipvpn_log_append("%p says: packet has invalid mac\n", peer);
					return 0;
				}

				if(!chipvpn_bitmap_validate(&peer->bitmap, ntohll(packet->counter))) {
					chipvpn_log_append("%p says: rejected replayed packet\n", peer);
					return 0;
				}

				ip_hdr_t *ip_hdr = (ip_hdr_t*)data;
				if(ip_hdr->version != 4) {
					return 0;
				}

				chipvpn_address_t src = {
					.ip = ip_hdr->src_addr
				};

				if(chipvpn_peer_get_by_allowip(&vpn->device->peers, &src) != peer) {
					chipvpn_log_append("%p says: invalid allow ip [%s]\n", peer, chipvpn_address_to_char(&src));
					return 0;
				}

				peer->rx += r - sizeof(chipvpn_packet_data_t);
				chipvpn_device_write(vpn->device, data, r - sizeof(chipvpn_packet_data_t));
			}
			break;
			case CHIPVPN_PACKET_PING: {
				if(r < sizeof(chipvpn_packet_ping_t)) {
					return 0;
				}

				chipvpn_packet_ping_t *packet = (chipvpn_packet_ping_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_session(&vpn->device->peers, ntohl(packet->session));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}
				
				return chipvpn_peer_recv_ping(peer, packet, &addr);
			}
			break;
		}
		return 0;
	}
	return 0;
}

void chipvpn_cleanup(chipvpn_t *vpn) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&vpn->device->peers); p != chipvpn_list_end(&vpn->device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	}

	chipvpn_device_free(vpn->device);
	chipvpn_socket_free(vpn->socket);

	free(vpn);
}