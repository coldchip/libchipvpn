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
#include "device.h"
#include "peer.h"
#include "tun.h"
#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

chipvpn_t *chipvpn_init(char *config) {
	chipvpn_t *vpn = malloc(sizeof(chipvpn_t));

	chipvpn_device_t *device = NULL;
	chipvpn_tun_t    *tun    = NULL;
	chipvpn_socket_t *sock   = NULL;

	setbuf(stdout, 0);

	if(sodium_init() == -1) {
		return NULL;
	}

	/* create device config */

	device = chipvpn_device_create(config);
	if(!device) {
		return NULL;
	}

	/* create tunnel socket */

	tun = chipvpn_tun_create(NULL);
	if(!tun) {
		return NULL;
	}

	/* create vpn socket */

	sock = chipvpn_socket_create();
	if(!sock) {
		return NULL;
	}

	/* set tunnel ip */

	if(!chipvpn_tun_set_ip(tun, &device->address)) {
		return NULL;
	}
	if(!chipvpn_tun_set_mtu(tun, device->mtu)) {
		return NULL;
	}
	if(!chipvpn_tun_ifup(tun)) {
		return NULL;
	}

	if(device->flag & CHIPVPN_DEVICE_BIND) {
		if(!chipvpn_socket_bind(sock, &device->bind)) {
			return NULL;
		}
	}

	if(device->flag & CHIPVPN_DEVICE_POSTUP) {
		if(system(device->postup) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}

	vpn->device = device;
	vpn->tun = tun;
	vpn->sock = sock;

	vpn->tun_can_read = 0;
	vpn->tun_can_write = 0;
	vpn->sock_can_read = 0;
	vpn->sock_can_write = 0;

	vpn->counter = 0;
	vpn->sender_id = 0;
	vpn->last_update = 0;

	return vpn;
}

void chipvpn_wait(chipvpn_t *vpn) {
	struct timeval tv;
	fd_set rdset, wdset, edset;

	tv.tv_sec = 0;
	tv.tv_usec = 250000;

	FD_ZERO(&rdset);
	FD_ZERO(&wdset);
	FD_ZERO(&edset);

	int max = 0;

	chipvpn_fdset(vpn, &rdset, &wdset, &max);

	if(select(max + 1, &rdset, &wdset, &edset, &tv) >= 0) {
		chipvpn_isset(vpn, &rdset, &wdset);
	}
}

void chipvpn_fdset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset, int *max) {
	int tun_fd  = vpn->tun->fd;
	int sock_fd = vpn->sock->fd;

	FD_CLR(tun_fd, rdset);
	FD_CLR(tun_fd, wdset);
	FD_CLR(sock_fd, wdset);
	FD_CLR(sock_fd, rdset);

	if(!vpn->tun_can_read)   FD_SET(tun_fd, rdset);
	if(!vpn->tun_can_write)  FD_SET(tun_fd, wdset);
	if(!vpn->sock_can_write) FD_SET(sock_fd, wdset);
	if(!vpn->sock_can_read)  FD_SET(sock_fd, rdset);

	*max = MAX(tun_fd, sock_fd);
}

void chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset) {
	int tun_fd  = vpn->tun->fd;
	int sock_fd = vpn->sock->fd;
	
	if(FD_ISSET(tun_fd, rdset))  vpn->tun_can_read  = 1;
	if(FD_ISSET(tun_fd, wdset))  vpn->tun_can_write = 1;
	if(FD_ISSET(sock_fd, rdset)) vpn->sock_can_read  = 1;
	if(FD_ISSET(sock_fd, wdset)) vpn->sock_can_write = 1;
}

int chipvpn_service(chipvpn_t *vpn) {
	/* peer lifecycle service */
	if(chipvpn_get_time() - vpn->last_update >= 1 && vpn->sock_can_write) {
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
				chipvpn_socket_write(vpn->sock, &auth, sizeof(auth), &peer->address);
				vpn->sock_can_write = 0;
			}

			/* attempt to disconnect from peer */
			if(peer->state == PEER_CONNECTED && peer->action == PEER_ACTION_DISCONNECT) {
				chipvpn_packet_deauth_t deauth = {};
				deauth.header.type = htonl(3);
				deauth.receiver_id = htonl(peer->receiver_id);

				chipvpn_socket_write(vpn->sock, &deauth, sizeof(deauth), &peer->address);
				vpn->sock_can_write = 0;
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

					chipvpn_socket_write(vpn->sock, &ping, sizeof(ping), &peer->address);
					vpn->sock_can_write = 0;
				}
			}
		}
		vpn->last_update = chipvpn_get_time();
	}

	/* tun => sock */
	if(vpn->tun_can_read) {
		char buf[vpn->device->mtu];
		int r = chipvpn_tun_read(vpn->tun, buf, sizeof(buf));
		vpn->tun_can_read = 0;

		if(r <= 0 || !vpn->sock_can_write) {
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

		chipvpn_socket_write(vpn->sock, buffer, sizeof(chipvpn_packet_data_t) + r, &peer->address);
		vpn->sock_can_write = 0;
	}

	/* sock => tun */
	if(vpn->sock_can_read) {
		char buffer[sizeof(chipvpn_packet_t) + vpn->device->mtu];
		chipvpn_address_t addr;

		int r = chipvpn_socket_read(vpn->sock, buffer, sizeof(buffer), &addr);
		vpn->sock_can_read = 0;

		if(r <= sizeof(chipvpn_packet_header_t)) {
			return 0;
		}

		chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
		switch(ntohl(header->type)) {
			case 0: {
				if(r < sizeof(chipvpn_packet_auth_t) || !vpn->sock_can_write) {
					break;
				}

				chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(&vpn->device->peers, packet->keyhash);
				if(!peer) {
					break;
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

					chipvpn_socket_write(vpn->sock, &auth, sizeof(chipvpn_packet_auth_t), &addr);
					vpn->sock_can_write = 0;
				}
			}
			break;
			case 1: {
				if(r < sizeof(chipvpn_packet_data_t) || !vpn->tun_can_write) {
					break;
				}

				chipvpn_packet_data_t *packet = (chipvpn_packet_data_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&vpn->device->peers, ntohl(packet->receiver_id));
				if(!peer || peer->state != PEER_CONNECTED) {
					break;
				}

				char *buf = buffer + sizeof(chipvpn_packet_data_t);

				chipvpn_crypto_xcrypt(peer->crypto, buf, r - sizeof(chipvpn_packet_data_t), ntohll(packet->counter));

				chipvpn_address_t src = {};
				src.ip = ((ip_packet_t*)buf)->src_addr;

				if(chipvpn_peer_get_by_allowip(&vpn->device->peers, &src) == peer) {
					peer->rx += r - sizeof(chipvpn_packet_data_t);

					chipvpn_tun_write(vpn->tun, buf, r - sizeof(chipvpn_packet_data_t));
					vpn->tun_can_write = 0;
				}
			}
			break;
			case 2: {
				if(r < sizeof(chipvpn_packet_ping_t)) {
					break;
				}

				chipvpn_packet_ping_t *packet = (chipvpn_packet_ping_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&vpn->device->peers, ntohl(packet->receiver_id));
				if(!peer || peer->state != PEER_CONNECTED) {
					break;
				}

				peer->last_ping = chipvpn_get_time();
			}
			break;
		}
	}
	return 0;
}

void chipvpn_print_stats(chipvpn_t *vpn) {
	chipvpn_log("--------------------");
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&vpn->device->peers); p != chipvpn_list_end(&vpn->device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		chipvpn_log("peer [%i] tx: [%lli] rx: [%lli] connected: [%i]", peer->sender_id, peer->tx, peer->rx, peer->state);
	}
	chipvpn_log("--------------------");
}

void chipvpn_cleanup(chipvpn_t *vpn) {
	if(vpn->device->flag & CHIPVPN_DEVICE_POSTDOWN) {
		if(system(vpn->device->postdown) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}

	chipvpn_device_free(vpn->device);
	chipvpn_tun_free(vpn->tun);
	chipvpn_socket_free(vpn->sock);
}

char *chipvpn_format_bytes(uint64_t bytes) {
	char *suffix[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"};
	char length = sizeof(suffix) / sizeof(suffix[0]);

	int i = 0;
	double dblBytes = bytes;

	if(bytes > 1024) {
		for (i = 0; (bytes / 1024) > 0 && i < length - 1; i++, bytes /= 1024) {
			dblBytes = bytes / 1024.0;
		}
	}

	static char output[200];
	sprintf(output, "%.02lf %s", dblBytes, suffix[i]);
	return output;
}

void chipvpn_log(const char *format, ...) {
	va_list args;
	va_start(args, format);

	#ifdef _WIN32
	printf("[ChipVPN] ");
	vprintf(format, args);
	printf("\n");
	#else
	printf("\033[0;36m[ChipVPN] ");
	vprintf(format, args);
	printf("\033[0m\n");
	#endif
	
	va_end(args);
}

uint32_t chipvpn_get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}