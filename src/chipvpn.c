#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
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

bool quit = false;

chipvpn_device_t *device = NULL;

chipvpn_tun_t    *tun = NULL;
chipvpn_socket_t *sock = NULL;

chipvpn_socket_t *mgmt = NULL;

void chipvpn_setup(char *config) {
	signal(SIGINT, chipvpn_exit);
	signal(SIGTERM, chipvpn_exit);

	#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, chipvpn_exit);
	signal(SIGQUIT, chipvpn_exit);
	#endif

	chipvpn_init(config);
	chipvpn_loop(config);
	chipvpn_cleanup();
}

void chipvpn_init(char *config) {
	setbuf(stdout, 0);
	chipvpn_log("ColdChip ChipVPN v1.2");

	if(sodium_init() == -1) {
		chipvpn_error("unable to initialize libsodium crypto");
	}

	/* create device config */

	device = chipvpn_device_create(config);
	if(!device) {
		chipvpn_error("unable to load config");
	}

	/* create tunnel socket */

	tun = chipvpn_tun_create(device->name);
	if(!tun) {
		chipvpn_error("unable to create tunnel interface");
	}

	/* create vpn socket */

	sock = chipvpn_socket_create();
	if(!sock) {
		chipvpn_error("unable to create socket");
	}

	/* create management socket */

	mgmt = chipvpn_socket_create();
	if(!mgmt) {
		chipvpn_error("unable to create socket");
	}

	chipvpn_address_t mgmt_addr;
	if(!chipvpn_address_set_ip(&mgmt_addr, "127.0.0.1")) {
		chipvpn_error("invalid ip address");
	}
	mgmt_addr.port = 29288;

	if(!chipvpn_socket_bind(mgmt, &mgmt_addr)) {
		chipvpn_error("socket bind failed");
	}

	/* set tunnel ip */

	if(!chipvpn_tun_set_ip(tun, &device->address)) {
		chipvpn_error("set tun ip failed");
	}
	if(!chipvpn_tun_set_mtu(tun, device->mtu)) {
		chipvpn_error("set tun mtu failed");
	}
	if(!chipvpn_tun_ifup(tun)) {
		chipvpn_error("tun up failed");
	}

	if(device->flag & CHIPVPN_DEVICE_BIND) {
		if(!chipvpn_socket_bind(sock, &device->bind)) {
			chipvpn_error("socket bind failed");
		}
	}

	if(device->flag & CHIPVPN_DEVICE_POSTUP) {
		if(system(device->postup) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}
}

void chipvpn_loop(char *config) {
	uint32_t chipvpn_last_update = 0;

	uint64_t counter = 0;
	uint64_t sender_id = 0;

	struct timeval tv;
	fd_set rdset, wdset;

	FD_ZERO(&rdset);
	FD_ZERO(&wdset);

	int tun_can_read = 0;
	int tun_can_write = 0;
	int sock_can_read = 0;
	int sock_can_write = 0;
	int mgmt_can_read = 0;
	int mgmt_can_write = 0;

	int tun_fd  = tun->fd;
	int sock_fd = sock->fd;
	int mgmt_fd = mgmt->fd;

	while(!quit) {
		tv.tv_sec = 0;
		tv.tv_usec = 250000;

		FD_CLR(tun_fd, &rdset);
		FD_CLR(tun_fd, &wdset);
		FD_CLR(sock_fd, &wdset);
		FD_CLR(sock_fd, &rdset);
		FD_CLR(mgmt_fd, &wdset);
		FD_CLR(mgmt_fd, &rdset);

		if(!tun_can_read)   FD_SET(tun_fd, &rdset);
		if(!tun_can_write)  FD_SET(tun_fd, &wdset);
		if(!sock_can_write) FD_SET(sock_fd, &wdset);
		if(!sock_can_read)  FD_SET(sock_fd, &rdset);
		if(!mgmt_can_write) FD_SET(mgmt_fd, &wdset);
		if(!mgmt_can_read)  FD_SET(mgmt_fd, &rdset);

		if(select(MAX(MAX(tun_fd, mgmt_fd), sock_fd) + 1, &rdset, &wdset, NULL, &tv) >= 0) {

			if(FD_ISSET(tun_fd, &rdset))  tun_can_read  = 1;
			if(FD_ISSET(tun_fd, &wdset))  tun_can_write = 1;
			if(FD_ISSET(sock_fd, &rdset)) sock_can_read  = 1;
			if(FD_ISSET(sock_fd, &wdset)) sock_can_write = 1;
			if(FD_ISSET(mgmt_fd, &rdset)) mgmt_can_read  = 1;
			if(FD_ISSET(mgmt_fd, &wdset)) mgmt_can_write = 1;

			/* peer lifecycle service */
			if(sock_can_write && chipvpn_get_time() - chipvpn_last_update >= 1) {
				chipvpn_device_reload_config(device, config);
				chipvpn_print_stats();
				for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
					chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
					if(peer->state == PEER_DISCONNECTED && peer->connect == true) {
						peer->sender_id = ++sender_id;

						chipvpn_packet_auth_t auth = {};
						auth.header.type = htonl(0);
						auth.sender_id = htonl(peer->sender_id);
						randombytes_buf(auth.nonce, sizeof(auth.nonce));
						crypto_hash_sha256((unsigned char*)auth.keyhash, (unsigned char*)peer->crypto->key, sizeof(peer->crypto->key));
						auth.ack = true;
						chipvpn_socket_write(sock, &auth, sizeof(auth), &peer->address);
						sock_can_write = 0;
					}
					if(peer->state == PEER_CONNECTED) {
						if(chipvpn_get_time() - peer->last_ping > 10) {
							peer->state = PEER_DISCONNECTED;
						} else {
							chipvpn_packet_ping_t ping = {};
							ping.header.type = htonl(2);
							ping.receiver_id = htonl(peer->receiver_id);

							chipvpn_socket_write(sock, &ping, sizeof(ping), &peer->address);
							sock_can_write = 0;
						}
					}
				}
				chipvpn_last_update = chipvpn_get_time();
			}

			/* tun => sock */
			if(tun_can_read && sock_can_write) {
				char buf[device->mtu];
				int r = chipvpn_tun_read(tun, buf, sizeof(buf));
				tun_can_read = 0;

				if(r <= 0) {
					continue;
				}

				chipvpn_address_t dst = {};
				dst.ip = ((ip_packet_t*)buf)->dst_addr;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_allowip(&device->peers, &dst);
				if(!peer || peer->state != PEER_CONNECTED) {
					continue;
				}

				char buffer[sizeof(chipvpn_packet_data_t) + r];

				chipvpn_packet_data_t data = {};
				data.header.type = htonl(1);
				data.receiver_id = htonl(peer->receiver_id);
				data.counter = htonll(counter);

				chipvpn_crypto_xcrypt(peer->crypto, buf, r, counter);
				memcpy(buffer, &data, sizeof(data));
				memcpy(buffer + sizeof(data), buf, r);

				counter++;

				peer->tx += r;

				chipvpn_socket_write(sock, buffer, sizeof(chipvpn_packet_data_t) + r, &peer->address);
				sock_can_write = 0;
			}

			/* sock => tun */
			if(sock_can_read && tun_can_write) {
				char buffer[sizeof(chipvpn_packet_t) + device->mtu];
				chipvpn_address_t addr;

				int r = chipvpn_socket_read(sock, buffer, sizeof(buffer), &addr);
				sock_can_read = 0;

				if(r <= sizeof(chipvpn_packet_header_t)) {
					continue;
				}

				chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
				switch(ntohl(header->type)) {
					case 0: {
						if(r < sizeof(chipvpn_packet_auth_t)) {
							break;
						}

						chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

						chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(&device->peers, packet->keyhash);
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
							peer->sender_id = ++sender_id;

							chipvpn_packet_auth_t auth = {};
							auth.header.type = htonl(0);
							auth.sender_id = htonl(peer->sender_id);
							memcpy(auth.nonce, packet->nonce, sizeof(auth.nonce));
							memcpy(auth.keyhash, packet->keyhash, sizeof(auth.keyhash));
							auth.ack = false;

							chipvpn_socket_write(sock, &auth, sizeof(chipvpn_packet_auth_t), &addr);
							sock_can_write = 0;
						}
					}
					break;
					case 1: {
						if(r < sizeof(chipvpn_packet_data_t)) {
							break;
						}

						chipvpn_packet_data_t *packet = (chipvpn_packet_data_t*)buffer;

						chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&device->peers, ntohl(packet->receiver_id));
						if(!peer || peer->state != PEER_CONNECTED) {
							break;
						}

						char *buf = buffer + sizeof(chipvpn_packet_data_t);

						chipvpn_crypto_xcrypt(peer->crypto, buf, r - sizeof(chipvpn_packet_data_t), ntohll(packet->counter));

						chipvpn_address_t src = {};
						src.ip = ((ip_packet_t*)buf)->src_addr;

						if(chipvpn_peer_get_by_allowip(&device->peers, &src) == peer) {
							peer->rx += r - sizeof(chipvpn_packet_data_t);

							chipvpn_tun_write(tun, buf, r - sizeof(chipvpn_packet_data_t));
							tun_can_write = 0;
						}
					}
					break;
					case 2: {
						if(r < sizeof(chipvpn_packet_ping_t)) {
							break;
						}

						chipvpn_packet_ping_t *packet = (chipvpn_packet_ping_t*)buffer;

						chipvpn_peer_t *peer = chipvpn_peer_get_by_index(&device->peers, ntohl(packet->receiver_id));
						if(!peer || peer->state != PEER_CONNECTED) {
							break;
						}

						peer->last_ping = chipvpn_get_time();
					}
					break;
				}
			}

			if(mgmt_can_read && mgmt_can_write) {
				chipvpn_address_t addr;

				char buffer[8192];
				int r = chipvpn_socket_read(mgmt, buffer, sizeof(buffer), &addr);
				mgmt_can_read = 0;

				buffer[r] = '\0';

				if(strstr(buffer, "quit") != NULL) {
					quit = true;
				}

				if(strstr(buffer, "ifup") != NULL) {
					chipvpn_tun_ifup(tun);
				}

				if(strstr(buffer, "ifdown") != NULL) {
					chipvpn_tun_ifdown(tun);
				}

				uint64_t online = 0;

				for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
					chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
					if(peer->state == PEER_CONNECTED) {
						online++;
					}
				}

				char reply[8192];
				sprintf(reply, "%li", online);
				chipvpn_socket_write(mgmt, reply, strlen(reply), &addr);
				mgmt_can_write = 0;
			}
		}
	}
}

void chipvpn_print_stats() {
	chipvpn_log("--------------------");
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		chipvpn_log("peer [%i] tx: [%lli] rx: [%lli] connected: [%i]", peer->sender_id, peer->tx, peer->rx, peer->state);
	}
	chipvpn_log("--------------------");
}

void chipvpn_cleanup() {
	if(device->flag & CHIPVPN_DEVICE_POSTDOWN) {
		if(system(device->postdown) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}

	chipvpn_device_free(device);

	chipvpn_tun_free(tun);
	chipvpn_socket_free(sock);
	chipvpn_socket_free(mgmt);
}

void chipvpn_exit(int type) {
	quit = true;
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