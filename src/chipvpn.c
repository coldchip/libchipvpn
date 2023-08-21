#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sodium.h>
#include "crypto.h"
#include "chipvpn.h"
#include "socket.h"
#include "packet.h"
#include "address.h"
#include "peer.h"
#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

chipvpn_t *chipvpn_create(chipvpn_device_t *device, chipvpn_address_t *bind) {
	chipvpn_t *vpn = malloc(sizeof(chipvpn_t));

	setbuf(stdout, 0);
	if(sodium_init() == -1) {
		return NULL;
	}

	/* create vpn socket */
	chipvpn_socket_t *socket = chipvpn_socket_create();
	if(!socket) {
		return NULL;
	}

	if(bind) {
		if(!chipvpn_socket_bind(socket, bind)) {
			return NULL;
		}
	}

	vpn->device = device;
	vpn->socket = socket;

	vpn->device_can_read = 0;
	vpn->device_can_write = 0;
	vpn->socket_can_read = 0;
	vpn->socket_can_write = 0;

	vpn->counter = 0;
	vpn->sender_id = 0;
	vpn->last_update = 0;

	return vpn;
}

void chipvpn_wait(chipvpn_t *vpn) {
	fd_set rdset, wdset;
	FD_ZERO(&rdset);
	FD_ZERO(&wdset);

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 250000;

	int max = 0;

	chipvpn_fdset(vpn, &rdset, &wdset, &max);

	if(select(max + 1, &rdset, &wdset, NULL, &tv) >= 0) {
		chipvpn_isset(vpn, &rdset, &wdset);
	}
}

void chipvpn_fdset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset, int *max) {
	int device_fd  = vpn->device->fd;
	int socket_fd = vpn->socket->fd;

	if(vpn->device_can_read)  FD_CLR(device_fd, rdset); else FD_SET(device_fd, rdset);
	if(vpn->device_can_write) FD_CLR(device_fd, wdset); else FD_SET(device_fd, wdset);
	if(vpn->socket_can_write) FD_CLR(socket_fd, wdset); else FD_SET(socket_fd, wdset);
	if(vpn->socket_can_read)  FD_CLR(socket_fd, rdset); else FD_SET(socket_fd, rdset);

	*max = MAX(device_fd, socket_fd);
}

void chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset) {
	int device_fd  = vpn->device->fd;
	int socket_fd = vpn->socket->fd;
	
	if(FD_ISSET(device_fd, rdset)) vpn->device_can_read  = 1;
	if(FD_ISSET(device_fd, wdset)) vpn->device_can_write = 1;
	if(FD_ISSET(socket_fd, rdset)) vpn->socket_can_read  = 1;
	if(FD_ISSET(socket_fd, wdset)) vpn->socket_can_write = 1;
}

int chipvpn_service(chipvpn_t *vpn) {
	/* peer lifecycle service */
	if(chipvpn_get_time() - vpn->last_update >= 1 && vpn->socket_can_write) {
		for(chipvpn_list_node_t *p = chipvpn_list_begin(&vpn->device->peers); p != chipvpn_list_end(&vpn->device->peers); p = chipvpn_list_next(p)) {
			chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
			
			/* check against connect/disconnect timeout timers */
			if(chipvpn_get_time() > peer->timeout && peer->action != PEER_ACTION_NONE) {
				peer->action = PEER_ACTION_NONE;
				peer->state = PEER_DISCONNECTED;
			}

			/* attempt to connect to peer */
			if(peer->state == PEER_DISCONNECTED && peer->action == PEER_ACTION_CONNECT) {
				peer->sender_id = ++vpn->sender_id;

				chipvpn_packet_auth_t auth = {};
				auth.header.type = htonl(0);
				auth.sender_id = htonl(peer->sender_id);
				randombytes_buf(auth.nonce, sizeof(auth.nonce));
				crypto_hash_sha256((unsigned char*)auth.keyhash, (unsigned char*)peer->crypto->key, sizeof(peer->crypto->key));
				auth.ack = true;
				chipvpn_socket_write(vpn->socket, &auth, sizeof(auth), &peer->address);
				vpn->socket_can_write = 0;
			}

			/* attempt to disconnect from peer */
			if(peer->state == PEER_CONNECTED && peer->action == PEER_ACTION_DISCONNECT) {
				chipvpn_packet_deauth_t deauth = {};
				deauth.header.type = htonl(3);
				deauth.receiver_id = htonl(peer->receiver_id);

				chipvpn_socket_write(vpn->socket, &deauth, sizeof(deauth), &peer->address);
				vpn->socket_can_write = 0;
			}

			/* ping peers and disconnect unping peers */
			if(peer->state == PEER_CONNECTED) {
				if(chipvpn_get_time() - peer->last_ping > 10) {
					peer->action = PEER_ACTION_NONE;
					peer->state = PEER_DISCONNECTED;
				} else {
					chipvpn_packet_ping_t ping = {};
					ping.header.type = htonl(2);
					ping.receiver_id = htonl(peer->receiver_id);

					chipvpn_socket_write(vpn->socket, &ping, sizeof(ping), &peer->address);
					vpn->socket_can_write = 0;
				}
			}
		}
		vpn->last_update = chipvpn_get_time();
	}

	/* tunnel => socket */
	if(vpn->device_can_read) {
		char buf[vpn->device->mtu];
		int r = chipvpn_device_read(vpn->device, buf, sizeof(buf));
		vpn->device_can_read = 0;

		if(r <= 0 || !vpn->socket_can_write) {
			return 0;
		}

		chipvpn_address_t dst = {};
		dst.ip = ((ip_packet_t*)buf)->dst_addr;

		chipvpn_peer_t *peer = chipvpn_peer_get_by_allowip(&vpn->device->peers, &dst);
		if(!peer || peer->state != PEER_CONNECTED) {
			return 0;
		}

		char buffer[sizeof(chipvpn_packet_data_t) + r];

		chipvpn_packet_data_t data = {};
		data.header.type = htonl(1);
		data.receiver_id = htonl(peer->receiver_id);
		data.counter = htonll(vpn->counter);

		chipvpn_crypto_xcrypt(peer->crypto, buf, r, vpn->counter);
		memcpy(buffer, &data, sizeof(data));
		memcpy(buffer + sizeof(data), buf, r);

		vpn->counter++;

		peer->tx += r;

		chipvpn_socket_write(vpn->socket, buffer, sizeof(chipvpn_packet_data_t) + r, &peer->address);
		vpn->socket_can_write = 0;
	}

	/* socket => tunnel */
	if(vpn->socket_can_read) {
		char buffer[sizeof(chipvpn_packet_t) + vpn->device->mtu];
		chipvpn_address_t addr;

		int r = chipvpn_socket_read(vpn->socket, buffer, sizeof(buffer), &addr);
		vpn->socket_can_read = 0;

		if(r <= sizeof(chipvpn_packet_header_t)) {
			return 0;
		}

		chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
		switch(ntohl(header->type)) {
			case 0: {
				if(r < sizeof(chipvpn_packet_auth_t) || !vpn->socket_can_write) {
					return 0;
				}

				chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(&vpn->device->peers, packet->keyhash);
				if(!peer) {
					return 0;
				}

				peer->receiver_id = ntohl(packet->sender_id);
				peer->address = addr;
				peer->action = PEER_ACTION_NONE;
				peer->state = PEER_CONNECTED;
				peer->tx = 0;
				peer->rx = 0;
				peer->last_ping = chipvpn_get_time();

				chipvpn_crypto_set_nonce(peer->crypto, packet->nonce);

				if(packet->ack == true) {
					peer->sender_id = ++vpn->sender_id;

					chipvpn_packet_auth_t auth = {};
					auth.header.type = htonl(0);
					auth.sender_id = htonl(peer->sender_id);
					memcpy(auth.nonce, packet->nonce, sizeof(auth.nonce));
					memcpy(auth.keyhash, packet->keyhash, sizeof(auth.keyhash));
					auth.ack = false;

					chipvpn_socket_write(vpn->socket, &auth, sizeof(chipvpn_packet_auth_t), &addr);
					vpn->socket_can_write = 0;
				}
			}
			break;
			case 1: {
				if(r < sizeof(chipvpn_packet_data_t) || !vpn->device_can_write) {
					return 0;
				}

				chipvpn_packet_data_t *packet = (chipvpn_packet_data_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&vpn->device->peers, ntohl(packet->receiver_id));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}

				char *buf = buffer + sizeof(chipvpn_packet_data_t);

				chipvpn_crypto_xcrypt(peer->crypto, buf, r - sizeof(chipvpn_packet_data_t), ntohll(packet->counter));

				chipvpn_address_t src = {};
				src.ip = ((ip_packet_t*)buf)->src_addr;

				if(chipvpn_peer_get_by_allowip(&vpn->device->peers, &src) == peer) {
					peer->rx += r - sizeof(chipvpn_packet_data_t);

					chipvpn_device_write(vpn->device, buf, r - sizeof(chipvpn_packet_data_t));
					vpn->device_can_write = 0;
				}
			}
			break;
			case 2: {
				if(r < sizeof(chipvpn_packet_ping_t)) {
					return 0;
				}

				chipvpn_packet_ping_t *packet = (chipvpn_packet_ping_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&vpn->device->peers, ntohl(packet->receiver_id));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}

				peer->last_ping = chipvpn_get_time();
			}
			break;
		}
	}
	return 0;
}

void chipvpn_cleanup(chipvpn_t *vpn) {
	chipvpn_socket_free(vpn->socket);
}

uint32_t chipvpn_get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}