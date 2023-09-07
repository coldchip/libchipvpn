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

	return vpn;
}

void chipvpn_wait(chipvpn_t *vpn, uint64_t timeout) {
	fd_set rdset, wdset;
	FD_ZERO(&rdset);
	FD_ZERO(&wdset);

	struct timeval tv;
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

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

	for(chipvpn_peer_t *peer = vpn->device->peers; peer < &vpn->device->peers[vpn->device->peer_count]; ++peer) {
		if(chipvpn_get_time() - peer->last_check > 500) {
			peer->last_check = chipvpn_get_time();

			printf("%p says: current time: [%li] timeout: [%li] state: [%i]\n", peer, chipvpn_get_time(), peer->timeout, peer->state);

			/* disconnect unpinged peer and check against connect/disconnect timeout timers */
			if(chipvpn_get_time() > peer->timeout) {
				peer->state = PEER_DISCONNECTED;
			}

			/* attempt to connect to peer */
			if(peer->state == PEER_DISCONNECTED && peer->connect == true) {
				chipvpn_peer_connect(vpn->socket, peer, 1);
			}

			/* ping peers */
			if(peer->state == PEER_CONNECTED) {
				chipvpn_packet_ping_t ping = {};
				ping.header.type = htonl(2);
				ping.session = htonl(peer->outbound_session);

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

		chipvpn_peer_t *peer = chipvpn_peer_get_by_allowip(vpn->device->peers, vpn->device->peer_count, &dst);
		if(!peer || peer->state != PEER_CONNECTED) {
			return 0;
		}

		char buffer[sizeof(chipvpn_packet_data_t) + r];

		chipvpn_packet_data_t data = {};
		data.header.type = htonl(1);
		data.session = htonl(peer->outbound_session);
		data.counter = htonll(vpn->counter);

		chipvpn_crypto_xcrypt(&peer->outbound_crypto, buf, r, vpn->counter);
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

				chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(vpn->device->peers, vpn->device->peer_count, packet->keyhash);
				if(!peer) {
					return 0;
				}
				if(ntohll(packet->timestamp) <= peer->timestamp) {
					return 0;
				}

				peer->state = PEER_CONNECTED;
				peer->outbound_session = ntohl(packet->session);
				peer->address = addr;
				peer->timestamp = ntohll(packet->timestamp);
				peer->tx = 0;
				peer->rx = 0;
				peer->timeout = chipvpn_get_time() + 10000;

				char nonce2[crypto_stream_xchacha20_NONCEBYTES] = {
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
				};

				crypto_stream_xchacha20_xor_ic(
					(unsigned char*)&peer->outbound_crypto, 
					(unsigned char*)&packet->crypto, 
					sizeof(packet->crypto), 
					(unsigned char*)nonce2, 
					1024, 
					(unsigned char*)peer->key
				);

				printf("%p says: i'm authenticated and peer's session is %i\n", peer, peer->outbound_session);

				if(packet->ack) {
					printf("%p says: peer requested auth acknowledgement\n", peer);
					chipvpn_peer_connect(vpn->socket, peer, 0);
				}
			}
			break;
			case 1: {
				if(r < sizeof(chipvpn_packet_data_t)) {
					return 0;
				}

				chipvpn_packet_data_t *packet = (chipvpn_packet_data_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_session(vpn->device->peers, vpn->device->peer_count, ntohl(packet->session));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}
				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					return 0;
				}

				char *buf = buffer + sizeof(chipvpn_packet_data_t);

				chipvpn_crypto_xcrypt(&peer->inbound_crypto, buf, r - sizeof(chipvpn_packet_data_t), ntohll(packet->counter));

				chipvpn_address_t src = {};
				src.ip = ((ip_packet_t*)buf)->src_addr;

				if(chipvpn_peer_get_by_allowip(vpn->device->peers, vpn->device->peer_count, &src) != peer) {
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

				chipvpn_peer_t *peer = chipvpn_peer_get_by_session(vpn->device->peers, vpn->device->peer_count, ntohl(packet->session));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}
				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					return 0;
				}

				printf("%p says: received ping from peer\n", peer);

				peer->timeout = chipvpn_get_time() + 10000;
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