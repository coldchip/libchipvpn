#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "chacha20poly1305.h"
#include "chipvpn.h"
#include "socket.h"
#include "device.h"
#include "ipc.h"
#include "config.h"
#include "packet.h"
#include "address.h"
#include "peer.h"
#include "bitmap.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "log.h"
#include "util.h"

chipvpn_t *chipvpn_create(int tun_fd, int ipc_rfd, int ipc_wfd) {
	chipvpn_t *vpn = malloc(sizeof(chipvpn_t));

	setbuf(stdout, 0);

	/* create vpn device */
	chipvpn_device_t *device = chipvpn_device_create(tun_fd);
	if(!device) {
		return NULL;
	}

	/* create vpn socket */
	chipvpn_socket_t *sock = chipvpn_socket_create();
	if(!sock) {
		return NULL;
	}

	/* create control socket */
	chipvpn_ipc_t *ipc = chipvpn_ipc_create(ipc_rfd, ipc_wfd);
	if(!ipc) {
		return NULL;
	}

	vpn->device = device;
	vpn->socket = sock;
	vpn->ipc = ipc;

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
	
	if(select(max + 1, &rdset, &wdset, NULL, &tv) > 0) {
		chipvpn_isset(vpn, &rdset, &wdset);
	}
}

void chipvpn_fdset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset, int *max) {
	int device_max = 0, socket_max = 0, ipc_max = 0;

	chipvpn_device_preselect(vpn->device, rdset, wdset, &device_max);
	chipvpn_socket_preselect(vpn->socket, rdset, wdset, &socket_max);
	chipvpn_ipc_preselect(   vpn->ipc,    rdset, wdset, &ipc_max);

	*max = MAX(device_max, MAX(socket_max, ipc_max));
}

void chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset) {
	chipvpn_device_postselect(vpn->device, rdset, wdset);
	chipvpn_socket_postselect(vpn->socket, rdset, wdset);
	chipvpn_ipc_postselect(   vpn->ipc,    rdset, wdset);
}

int chipvpn_service(chipvpn_t *vpn) {
	/* peer lifecycle service */
	chipvpn_peer_service(&vpn->device->peers, vpn->socket);

	/* ipc */
	if(chipvpn_ipc_can_read(vpn->ipc) && chipvpn_ipc_can_write(vpn->ipc)) {
		char buffer[8192];
		int x = chipvpn_ipc_read(vpn->ipc, buffer, sizeof(buffer));
		buffer[x] = '\0';

		chipvpn_config_command(vpn, buffer);

		return chipvpn_ipc_write(vpn->ipc, "OK\n", 3);
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

		chipvpn_address_t dst = { .ip = ip_hdr->dst_addr };

		chipvpn_peer_t *peer = chipvpn_peer_get_by_allowip(&vpn->device->peers, &dst);
		if(!peer || peer->state != PEER_CONNECTED) {
			return 0;
		}

		peer->counter++;

		if(!chipvpn_peer_encrypt_payload(peer, data, r, peer->counter, header->mac)) {
			chipvpn_log_append("%p says: unable to encrypt payload\n", peer);
			return 0;
		}

		peer->tx += r;

		header->header.type = CHIPVPN_PACKET_DATA;
		header->session     = htonl(peer->outbound.session);
		header->counter     = htonll(peer->counter);

		return chipvpn_socket_write(vpn->socket, buffer, sizeof(chipvpn_packet_data_t) + r, &peer->address);
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
					chipvpn_log_append("keyhash hot found\n");
					return 0;
				}

				return chipvpn_peer_recv_connect(peer, vpn->socket, packet, &addr);
			}
			break;
			case CHIPVPN_PACKET_DATA: {
				if(r < sizeof(chipvpn_packet_data_t)) {
					return 0;
				}

				chipvpn_packet_data_t *packet      = (chipvpn_packet_data_t*)buffer;
				uint32_t               session     = ntohl(packet->session);
				uint64_t               counter     = ntohll(packet->counter);
				uint8_t               *data        = buffer + sizeof(chipvpn_packet_data_t);
				int                    data_size   = r - sizeof(chipvpn_packet_data_t);

				chipvpn_peer_t *peer = chipvpn_peer_get_by_inbound_session(&vpn->device->peers, session);
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}

				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					chipvpn_log_append("%p says: invalid src ip or src port\n", peer);
					return 0;
				}

				if(!chipvpn_peer_decrypt_payload(peer, data, data_size, counter, packet->mac)) {
					chipvpn_log_append("%p says: packet has invalid mac\n", peer);
					return 0;
				}

				/* must be after decrypt */
				if(!chipvpn_bitmap_validate(&peer->bitmap, counter)) {
					chipvpn_log_append("%p says: rejected replayed packet\n", peer);
					return 0;
				}

				ip_hdr_t *ip_hdr = (ip_hdr_t*)data;

				if(ip_hdr->version != 4) {
					return 0;
				}

				chipvpn_address_t src = { .ip = ip_hdr->src_addr };

				if(chipvpn_peer_get_by_allowip(&vpn->device->peers, &src) != peer) {
					chipvpn_log_append("%p says: invalid allow ip [%s]\n", peer, chipvpn_address_to_char(&src));
					return 0;
				}

				peer->rx += data_size;
				return chipvpn_device_write(vpn->device, data, data_size);
			}
			break;
			case CHIPVPN_PACKET_PING: {
				if(r < sizeof(chipvpn_packet_ping_t)) {
					return 0;
				}

				chipvpn_packet_ping_t *packet = (chipvpn_packet_ping_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_inbound_session(&vpn->device->peers, ntohl(packet->session));
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
	chipvpn_ipc_free(vpn->ipc);

	free(vpn);
}