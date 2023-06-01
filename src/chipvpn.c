#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
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
	chipvpn_t *chipvpn = malloc(sizeof(chipvpn_t));

	chipvpn_log("ColdChip ChipVPN v1.2");

	if(sodium_init() == -1) {
		chipvpn_error("unable to initialize libsodium crypto");
	}

	chipvpn->device = chipvpn_device_create(config);
	if(!chipvpn->device) {
		chipvpn_error("unable to load config");
	}

	chipvpn->tun = chipvpn_tun_create(chipvpn->device->name);
	if(!chipvpn->tun) {
		chipvpn_error("unable to create tunnel interface");
	}

	chipvpn->sock = chipvpn_socket_create();
	if(!chipvpn->sock) {
		chipvpn_error("unable to create socket");
	}

	if(!chipvpn_tun_set_ip(chipvpn->tun, &chipvpn->device->address)) {
		chipvpn_error("set tun ip failed");
	}
	if(!chipvpn_tun_set_mtu(chipvpn->tun, chipvpn->device->mtu)) {
		chipvpn_error("set tun mtu failed");
	}
	if(!chipvpn_tun_ifup(chipvpn->tun)) {
		chipvpn_error("tun up failed");
	}

	if(chipvpn->device->flag & CHIPVPN_DEVICE_BIND) {
		if(!chipvpn_socket_bind(chipvpn->sock, &chipvpn->device->bind)) {
			chipvpn_error("socket bind failed");
		}
	}

	if(chipvpn->device->flag & CHIPVPN_DEVICE_POSTUP) {
		if(system(chipvpn->device->postup) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}

	FD_ZERO(&chipvpn->rdset);
	FD_ZERO(&chipvpn->wdset);

	chipvpn->tun_can_read = 0;
	chipvpn->tun_can_write = 0;
	chipvpn->sock_can_read = 0;
	chipvpn->sock_can_write = 0;

	chipvpn->counter = 0;
	chipvpn->sender_id = 0;
	chipvpn->chipvpn_last_update = 0;

	return chipvpn;
}

void chipvpn_loop(chipvpn_t *chipvpn) {
	int tun_fd  = chipvpn->tun->fd;
	int sock_fd = chipvpn->sock->fd;

	chipvpn->tv.tv_sec = 0;
	chipvpn->tv.tv_usec = 250000;

	FD_CLR(tun_fd, &chipvpn->rdset);
	FD_CLR(tun_fd, &chipvpn->wdset);
	FD_CLR(sock_fd, &chipvpn->wdset);
	FD_CLR(sock_fd, &chipvpn->rdset);

	if(!chipvpn->tun_can_read)   FD_SET(tun_fd, &chipvpn->rdset);
	if(!chipvpn->tun_can_write)  FD_SET(tun_fd, &chipvpn->wdset);
	if(!chipvpn->sock_can_write) FD_SET(sock_fd, &chipvpn->wdset);
	if(!chipvpn->sock_can_read)  FD_SET(sock_fd, &chipvpn->rdset);

	if(select(MAX(sock_fd, tun_fd) + 1, &chipvpn->rdset, &chipvpn->wdset, NULL, &chipvpn->tv) >= 0) {

		if(FD_ISSET(tun_fd, &chipvpn->rdset))  chipvpn->tun_can_read  = 1;
		if(FD_ISSET(tun_fd, &chipvpn->wdset))  chipvpn->tun_can_write = 1;
		if(FD_ISSET(sock_fd, &chipvpn->rdset)) chipvpn->sock_can_read  = 1;
		if(FD_ISSET(sock_fd, &chipvpn->wdset)) chipvpn->sock_can_write = 1;

		/* peer lifecycle service */
		if(chipvpn->sock_can_write && chipvpn_get_time() - chipvpn->chipvpn_last_update >= 1) {
			for(chipvpn_list_node_t *p = chipvpn_list_begin(&chipvpn->device->peers); p != chipvpn_list_end(&chipvpn->device->peers); p = chipvpn_list_next(p)) {
				chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
				if(peer->state == PEER_DISCONNECTED && peer->connect == true) {
					peer->sender_id = ++chipvpn->sender_id;

					chipvpn_packet_auth_t auth = {};
					auth.header.type = htonl(0);
					auth.sender_id = htonl(peer->sender_id);
					randombytes_buf(auth.nonce, sizeof(auth.nonce));
					crypto_hash_sha256((unsigned char*)auth.keyhash, (unsigned char*)peer->crypto->key, sizeof(peer->crypto->key));
					auth.ack = true;
					chipvpn_socket_write(chipvpn->sock, &auth, sizeof(auth), &peer->address);
					chipvpn->sock_can_write = 0;
				}
				if(peer->state == PEER_CONNECTED) {
					if(chipvpn_get_time() - peer->last_ping > 10) {
						peer->state = PEER_DISCONNECTED;
					} else {
						chipvpn_packet_ping_t ping = {};
						ping.header.type = htonl(2);
						ping.receiver_id = htonl(peer->receiver_id);

						chipvpn_socket_write(chipvpn->sock, &ping, sizeof(ping), &peer->address);
						chipvpn->sock_can_write = 0;
					}
				}
			}
			chipvpn->chipvpn_last_update = chipvpn_get_time();
		}

		/* tun => sock */
		if(chipvpn->tun_can_read && chipvpn->sock_can_write) {
			char buf[chipvpn->device->mtu];
			int r = chipvpn_tun_read(chipvpn->tun, buf, sizeof(buf));
			chipvpn->tun_can_read = 0;

			if(r <= 0) {
				return;
			}

			chipvpn_address_t dst = {};
			dst.ip = ((ip_packet_t*)buf)->dst_addr;

			chipvpn_peer_t *peer = chipvpn_peer_get_by_allowip(&chipvpn->device->peers, &dst);
			if(!peer || peer->state != PEER_CONNECTED) {
				return;
			}

			char buffer[sizeof(chipvpn_packet_data_t) + r];

			chipvpn_packet_data_t data = {};
			data.header.type = htonl(1);
			data.receiver_id = htonl(peer->receiver_id);
			data.counter = htonll(chipvpn->counter);

			chipvpn_crypto_xcrypt(peer->crypto, buf, r, chipvpn->counter);
			memcpy(buffer, &data, sizeof(data));
			memcpy(buffer + sizeof(data), buf, r);

			chipvpn->counter++;

			peer->tx += r;

			chipvpn_socket_write(chipvpn->sock, buffer, sizeof(chipvpn_packet_data_t) + r, &peer->address);
			chipvpn->sock_can_write = 0;
		}

		/* sock => tun */
		if(chipvpn->sock_can_read && chipvpn->tun_can_write) {
			char buffer[sizeof(chipvpn_packet_t) + chipvpn->device->mtu];
			chipvpn_address_t addr;

			int r = chipvpn_socket_read(chipvpn->sock, buffer, sizeof(buffer), &addr);
			chipvpn->sock_can_read = 0;

			if(r <= sizeof(chipvpn_packet_header_t)) {
				return;
			}

			chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
			switch(ntohl(header->type)) {
				case 0: {
					if(r < sizeof(chipvpn_packet_auth_t)) {
						break;
					}

					chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

					chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(&chipvpn->device->peers, packet->keyhash);
					if(!peer) {
						break;
					}

					peer->receiver_id = ntohl(packet->sender_id);
					peer->address = addr;
					peer->state = PEER_CONNECTED;
					peer->tx = 0;
					peer->rx = 0;
					peer->last_ping = chipvpn_get_time();

					chipvpn_crypto_set_nonce(peer->crypto, packet->nonce);

					if(packet->ack == true) {
						peer->sender_id = ++chipvpn->sender_id;

						chipvpn_packet_auth_t auth = {};
						auth.header.type = htonl(0);
						auth.sender_id = htonl(peer->sender_id);
						memcpy(auth.nonce, packet->nonce, sizeof(auth.nonce));
						memcpy(auth.keyhash, packet->keyhash, sizeof(auth.keyhash));
						auth.ack = false;

						chipvpn_socket_write(chipvpn->sock, &auth, sizeof(chipvpn_packet_auth_t), &addr);
						chipvpn->sock_can_write = 0;
					}
				}
				break;
				case 1: {
					if(r < sizeof(chipvpn_packet_data_t)) {
						break;
					}

					chipvpn_packet_data_t *packet = (chipvpn_packet_data_t*)buffer;

					chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&chipvpn->device->peers, ntohl(packet->receiver_id));
					if(!peer || peer->state != PEER_CONNECTED) {
						break;
					}

					char *buf = buffer + sizeof(chipvpn_packet_data_t);

					chipvpn_crypto_xcrypt(peer->crypto, buf, r - sizeof(chipvpn_packet_data_t), ntohll(packet->counter));

					chipvpn_address_t src = {};
					src.ip = ((ip_packet_t*)buf)->src_addr;

					if(chipvpn_peer_get_by_allowip(&chipvpn->device->peers, &src) == peer) {
						peer->rx += r - sizeof(chipvpn_packet_data_t);

						chipvpn_tun_write(chipvpn->tun, buf, r - sizeof(chipvpn_packet_data_t));
						chipvpn->tun_can_write = 0;
					}
				}
				break;
				case 2: {
					if(r < sizeof(chipvpn_packet_ping_t)) {
						break;
					}

					chipvpn_packet_ping_t *packet = (chipvpn_packet_ping_t*)buffer;

					chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&chipvpn->device->peers, ntohl(packet->receiver_id));
					if(!peer || peer->state != PEER_CONNECTED) {
						break;
					}

					peer->last_ping = chipvpn_get_time();
				}
				break;
			}
		}
	}
}

void chipvpn_print_stats(chipvpn_t *chipvpn) {
	chipvpn_log("--------------------");
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&chipvpn->device->peers); p != chipvpn_list_end(&chipvpn->device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		chipvpn_log("peer: [%i] tx: [%llu] rx: [%llu] connected: [%i]", peer->sender_id, peer->tx, peer->rx, peer->state);
	}
	chipvpn_log("--------------------");
}

void chipvpn_cleanup(chipvpn_t *chipvpn) {
	if(chipvpn->device->flag & CHIPVPN_DEVICE_POSTDOWN) {
		if(system(chipvpn->device->postdown) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}

	chipvpn_tun_free(chipvpn->tun);
	chipvpn_socket_free(chipvpn->sock);
	chipvpn_device_free(chipvpn->device);

	free(chipvpn);
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

void chipvpn_error(const char *format, ...) {
	va_list args;
	va_start(args, format);

	#ifdef _WIN32
	printf("[ChipVPN] ");
	vprintf(format, args);
	printf("\n");
	#else
	printf("\033[0;31m[ChipVPN] ");
	vprintf(format, args);
	printf("\033[0m\n");
	#endif

	exit(1);
}

uint32_t chipvpn_get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}