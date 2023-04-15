#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include "crypto.h"
#include "chipvpn.h"
#include "socket.h"
#include "packet.h"
#include "address.h"
#include "device.h"
#include "peer.h"
#include "tun.h"

bool quit = false;

chipvpn_device_t *device = NULL;

void chipvpn_setup(char *file) {
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, chipvpn_exit);
	signal(SIGQUIT, chipvpn_exit);
	signal(SIGTERM, chipvpn_exit);
	signal(SIGHUP, chipvpn_exit);

	chipvpn_log("ChipVPN v2.1 beta");

	chipvpn_init(file);
	chipvpn_loop();
	chipvpn_cleanup();
}

void chipvpn_init(char *file) {
	device = chipvpn_device_create(file);
	if(!device) {
		chipvpn_error("unable to create config");
	}

	chipvpn_tun_setip(device->tun, &device->address, device->mtu, 2000);
	chipvpn_tun_ifup(device->tun);

	if(device->flag & CHIPVPN_DEVICE_BIND) {
		if(!chipvpn_socket_bind(device->sock, &device->bind)) {
			chipvpn_error("socket bind failed");
		}
	}

	if(device->flag & CHIPVPN_DEVICE_POSTUP) {
		if(system(device->postup) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}
}

void chipvpn_loop() {
	uint32_t chipvpn_last_update = 0;

	struct timeval tv;
	fd_set rdset, wdset;

	FD_ZERO(&rdset);
	FD_ZERO(&wdset);

	int tun_can_read = 0;
	int tun_can_write = 0;
	int sock_can_read = 0;
	int sock_can_write = 0;

	int tun_fd  = device->tun->fd;
	int sock_fd = device->sock->fd;

	chipvpn_packet_t packet;

	while(!quit) {
		tv.tv_sec = 0;
		tv.tv_usec = 250000;

		FD_CLR(tun_fd, &rdset);
		FD_CLR(tun_fd, &wdset);
		FD_CLR(sock_fd, &wdset);
		FD_CLR(sock_fd, &rdset);

		if(!tun_can_read)   FD_SET(tun_fd, &rdset);
		if(!tun_can_write)  FD_SET(tun_fd, &wdset);
		if(!sock_can_write) FD_SET(sock_fd, &wdset);
		if(!sock_can_read)  FD_SET(sock_fd, &rdset);

		if(chipvpn_get_time() - chipvpn_last_update >= 1) {
			for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
				chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
				if(peer->state == PEER_DISCONNECTED && peer->connect == true) {
					chipvpn_log("connecting to peer %i", peer->id);

					packet.header.type = 0;
					packet.auth_header.id = htonl(peer->id);

					chipvpn_socket_write(device->sock, &packet, sizeof(chipvpn_packet_header_t) + sizeof(chipvpn_packet_auth_t), &peer->endpoint);
				}
				if(peer->state == PEER_CONNECTED) {
					if(chipvpn_get_time() - peer->last_ping > 15) {
						chipvpn_log("timeout/disconnect peer %i", peer->id);
						peer->state = PEER_DISCONNECTED;
					} else {
						packet.header.type = 3;
						packet.ping_header.id = htonl(peer->id);

						chipvpn_socket_write(device->sock, &packet, sizeof(chipvpn_packet_header_t) + sizeof(chipvpn_packet_ping_t), &peer->address);
					}
				}
			}
			chipvpn_last_update = chipvpn_get_time();
		}

		if(select(MAX(sock_fd, tun_fd) + 1, &rdset, &wdset, NULL, &tv) >= 0) {

			if(FD_ISSET(tun_fd, &rdset))  tun_can_read  = 1;
			if(FD_ISSET(tun_fd, &wdset))  tun_can_write = 1;
			if(FD_ISSET(sock_fd, &rdset)) sock_can_read  = 1;
			if(FD_ISSET(sock_fd, &wdset)) sock_can_write = 1;

			if(tun_can_read && sock_can_write) {
				int r = chipvpn_tun_read(device->tun, packet.data, device->mtu);
				if(r > 0) {
					for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
						chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

						ip_packet_t *ip = (ip_packet_t*)&packet.data;
						chipvpn_address_t dst = {
							.ip = ip->dst_addr
						};

						if(chipvpn_address_cidr_match(&dst, &peer->allow) && peer->state == PEER_CONNECTED) {
							packet.header.type = 2;
							chipvpn_crypto_xcrypt(packet.data, r);

							chipvpn_socket_write(device->sock, &packet, sizeof(chipvpn_packet_header_t) + sizeof(chipvpn_packet_data_t) + r, &peer->address);
							sock_can_write = 0;
						}
					}
				}
				tun_can_read = 0;
			}

			if(sock_can_read && tun_can_write) {
				chipvpn_address_t addr;
				int r = chipvpn_socket_read(device->sock, &packet, sizeof(packet), &addr);
				if(r > 0) {
					switch(packet.header.type) {
						case 0:
						case 1: {
							if(r < sizeof(chipvpn_packet_header_t) + sizeof(chipvpn_packet_auth_t)) {
								break;
							}

							for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								if(ntohl(packet.auth_header.id) == peer->id) {
									peer->address = addr;
									peer->state = PEER_CONNECTED;
									peer->last_ping = chipvpn_get_time();
									chipvpn_log("connected to peer %i", peer->id);

									if(packet.header.type == 0) {
										packet.header.type = 1;
										packet.auth_header.id = packet.auth_header.id;
										chipvpn_socket_write(device->sock, &packet, sizeof(chipvpn_packet_header_t) + sizeof(chipvpn_packet_auth_t), &addr);
									}
									break;
								}
							}
						}
						break;
						case 2: {
							if(r < sizeof(chipvpn_packet_header_t) + sizeof(chipvpn_packet_data_t)) {
								break;
							}

							chipvpn_crypto_xcrypt(packet.data, r - sizeof(chipvpn_packet_header_t) + sizeof(chipvpn_packet_data_t));

							for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								ip_packet_t *ip = (ip_packet_t*)&packet.data;
								chipvpn_address_t src = {
									.ip = ip->src_addr
								};

								if(chipvpn_address_cidr_match(&src, &peer->allow) && peer->state == PEER_CONNECTED) {
									chipvpn_tun_write(device->tun, packet.data, r - sizeof(chipvpn_packet_header_t) + sizeof(chipvpn_packet_data_t));
									tun_can_write = 0;
								}
							}
						}
						break;
						case 3: {
							if(r < sizeof(chipvpn_packet_header_t) + sizeof(chipvpn_packet_ping_t)) {
								break;
							}

							for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								if(ntohl(packet.ping_header.id) == peer->id) {
									peer->last_ping = chipvpn_get_time();
								}
							}
						}
						break;
					}
				}
				sock_can_read = 0;
			}
		}
	}
}

void chipvpn_cleanup() {
	if(device->flag & CHIPVPN_DEVICE_POSTDOWN) {
		if(system(device->postdown) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}

	chipvpn_device_free(device);
}

void chipvpn_exit(int type) {
	quit = true;
	chipvpn_log("terminating...");
}

void chipvpn_log(const char *format, ...) {
	va_list args;
	va_start(args, format);

	printf("\033[0;36m[ChipVPN] ");
	vprintf(format, args);
	printf("\033[0m\n");
	
	va_end(args);
}

void chipvpn_error(const char *format, ...) {
	va_list args;
	va_start(args, format);

	printf("\033[0;31m[ChipVPN] ");
	vprintf(format, args);
	printf("\033[0m\n");

	exit(1);
}

uint32_t chipvpn_get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}