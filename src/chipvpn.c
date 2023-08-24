#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sodium.h>
#include "crypto.h"
#include "chipvpn.h"
#include "socket.h"
#include "packet.h"
#include "address.h"
#include "peer.h"

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

	vpn->counter = 0;
	vpn->sender_id = 0;

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
		
		if(chipvpn_get_time() - peer->last_check > 100) {
			peer->last_check = chipvpn_get_time();

			printf("%li %li %i\n", chipvpn_get_time(), peer->timeout, peer->state);

			/* disconnect unpinged peer and check against connect/disconnect timeout timers */
			if(chipvpn_get_time() > peer->timeout) {
				peer->state = PEER_DISCONNECTED;
			}

			/* attempt to connect to peer */
			if(peer->state == PEER_CONNECTING) {
				peer->sender_id = ++vpn->sender_id;

				chipvpn_packet_auth_t auth = {};
				auth.header.type = htonl(0);
				auth.sender_id = htonl(peer->sender_id);
				randombytes_buf(auth.nonce, sizeof(auth.nonce));
				crypto_hash_sha256((unsigned char*)auth.keyhash, (unsigned char*)peer->crypto->key, sizeof(peer->crypto->key));
				auth.ack = true;

				chipvpn_socket_write(vpn->socket, &auth, sizeof(auth), &peer->address);
			}

			/* attempt to disconnect from peer */
			if(peer->state == PEER_DISCONNECTING) {
				chipvpn_packet_deauth_t deauth = {};
				deauth.header.type = htonl(3);
				deauth.receiver_id = htonl(peer->receiver_id);
				deauth.ack = true;

				chipvpn_socket_write(vpn->socket, &deauth, sizeof(deauth), &peer->address);
			}

			/* ping peers */
			if(peer->state == PEER_CONNECTED) {
				chipvpn_packet_ping_t ping = {};
				ping.header.type = htonl(2);
				ping.receiver_id = htonl(peer->receiver_id);

				chipvpn_socket_write(vpn->socket, &ping, sizeof(ping), &peer->address);
			}
		}
	}

	/* tunnel => socket */
	if(chipvpn_device_can_read(vpn->device) && chipvpn_socket_can_write(vpn->socket)) {
		char buf[vpn->device->mtu];
		int r = chipvpn_device_read(vpn->device, buf, sizeof(buf));
		if(r <= 0) {
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
	}

	/* socket => tunnel */
	if(chipvpn_socket_can_read(vpn->socket) && chipvpn_device_can_write(vpn->device)) {
		char buffer[sizeof(chipvpn_packet_t) + vpn->device->mtu];
		chipvpn_address_t addr;

		int r = chipvpn_socket_read(vpn->socket, buffer, sizeof(buffer), &addr);
		if(r <= sizeof(chipvpn_packet_header_t)) {
			return 0;
		}

		chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
		switch(ntohl(header->type)) {
			case 0: {
				if(r < sizeof(chipvpn_packet_auth_t)) {
					return 0;
				}

				chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(&vpn->device->peers, packet->keyhash);
				if(!peer) {
					return 0;
				}

				peer->receiver_id = ntohl(packet->sender_id);
				peer->address = addr;
				peer->state = PEER_CONNECTED;
				peer->tx = 0;
				peer->rx = 0;
				peer->timeout = chipvpn_get_time() + 10000;

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
				}
			}
			break;
			case 1: {
				if(r < sizeof(chipvpn_packet_data_t)) {
					return 0;
				}

				chipvpn_packet_data_t *packet = (chipvpn_packet_data_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&vpn->device->peers, ntohl(packet->receiver_id));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}
				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					return 0;
				}

				char *buf = buffer + sizeof(chipvpn_packet_data_t);

				chipvpn_crypto_xcrypt(peer->crypto, buf, r - sizeof(chipvpn_packet_data_t), ntohll(packet->counter));

				chipvpn_address_t src = {};
				src.ip = ((ip_packet_t*)buf)->src_addr;

				if(chipvpn_peer_get_by_allowip(&vpn->device->peers, &src) != peer) {
					return 0;
				}

				peer->rx += r - sizeof(chipvpn_packet_data_t);
				chipvpn_device_write(vpn->device, buf, r - sizeof(chipvpn_packet_data_t));
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
				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					return 0;
				}

				printf("ping recv\n");

				peer->timeout = chipvpn_get_time() + 10000;
			}
			break;
			case 3: {
				if(r < sizeof(chipvpn_packet_deauth_t)) {
					return 0;
				}

				chipvpn_packet_deauth_t *packet = (chipvpn_packet_deauth_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&vpn->device->peers, ntohl(packet->receiver_id));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}
				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					return 0;
				}

				peer->state = PEER_DISCONNECTED;

				if(packet->ack == true) {
					chipvpn_packet_deauth_t deauth = {};
					deauth.header.type = htonl(3);
					deauth.receiver_id = htonl(peer->receiver_id);
					deauth.ack = false;

					chipvpn_socket_write(vpn->socket, &deauth, sizeof(deauth), &addr);
				}
			}
			break;
		}
		return 0;
	}
	return 0;
}

void chipvpn_cleanup(chipvpn_t *vpn) {
	chipvpn_socket_free(vpn->socket);
}

uint64_t chipvpn_get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}