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

chipvpn_device_t *config = NULL;

void chipvpn_setup(char *file) {
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, chipvpn_exit);
	signal(SIGQUIT, chipvpn_exit);
	signal(SIGTERM, chipvpn_exit);
	signal(SIGHUP, chipvpn_exit);

	chipvpn_log("ChipVPN v2.0");

	chipvpn_init(file);
	chipvpn_loop();
	chipvpn_cleanup();
}

void chipvpn_init(char *file) {
	config = chipvpn_device_create(file);
	if(!config) {
		chipvpn_error("unable to create config");
	}

	chipvpn_tun_setip(config->tun, &config->address, config->mtu, 2000);
	chipvpn_tun_ifup(config->tun);

	if(config->flag & CHIPVPN_DEVICE_BIND) {
		if(!chipvpn_socket_bind(config->sock, &config->bind)) {
			chipvpn_error("socket bind failed");
		}
	}

	if(config->flag & CHIPVPN_DEVICE_POSTUP) {
		if(system(config->postup) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}

	for(ListNode *p = list_begin(&config->peers); p != list_end(&config->peers); p = list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		if(peer->connect == true) {
			chipvpn_log("connecting to peer %i", peer->id);
			chipvpn_packet_t packet;
			packet.type = 0;
			packet.id = htonl(peer->id);

			chipvpn_socket_write(config->sock, &packet, sizeof(chipvpn_packet_t), &peer->endpoint);
		}
	}
}

void chipvpn_loop() {
	char             *packet        = alloca(sizeof(chipvpn_packet_t) + CHIPVPN_MTU);
	chipvpn_packet_t *packet_header = (chipvpn_packet_t*)packet;
	char             *packet_data   = sizeof(chipvpn_packet_t) + packet;

	struct timeval tv;
	fd_set rdset, wdset;

	FD_ZERO(&rdset);
	FD_ZERO(&wdset);

	int tun_can_read = 0;
	int tun_can_write = 0;
	int sock_can_read = 0;
	int sock_can_write = 0;

	int tun_fd  = config->tun->fd;
	int sock_fd = config->sock->fd;

	while(!quit) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_CLR(tun_fd, &rdset);
		FD_CLR(tun_fd, &wdset);
		FD_CLR(sock_fd, &wdset);
		FD_CLR(sock_fd, &rdset);

		if(!tun_can_read)   FD_SET(tun_fd, &rdset);
		if(!tun_can_write)  FD_SET(tun_fd, &wdset);
		if(!sock_can_write) FD_SET(sock_fd, &wdset);
		if(!sock_can_read)  FD_SET(sock_fd, &rdset);

		if(select(MAX(sock_fd, tun_fd) + 1, &rdset, &wdset, NULL, &tv) >= 0) {

			if(FD_ISSET(tun_fd, &rdset))  tun_can_read  = 1;
			if(FD_ISSET(tun_fd, &wdset))  tun_can_write = 1;
			if(FD_ISSET(sock_fd, &rdset)) sock_can_read  = 1;
			if(FD_ISSET(sock_fd, &wdset)) sock_can_write = 1;

			if(tun_can_read && sock_can_write) {
				char buf[CHIPVPN_MTU];
				int r = chipvpn_tun_read(config->tun, buf, sizeof(buf));
				if(r > 0) {
					ip_packet_t *ip = (ip_packet_t*)buf;

					for(ListNode *p = list_begin(&config->peers); p != list_end(&config->peers); p = list_next(p)) {
						chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

						chipvpn_address_t dst = {
							.ip = ip->dst_addr
						};

						if(chipvpn_address_cidr_match(&dst, &peer->allow)) {

							chipvpn_crypto_xcrypt(buf, r);

							packet_header->type = 2;
							memcpy(packet_data, buf, r);

							chipvpn_socket_write(config->sock, packet, sizeof(chipvpn_packet_t) + r, &peer->address);
							sock_can_write = 0;
						}
					}
				}
				tun_can_read = 0;
			}

			if(sock_can_read && tun_can_write) {
				chipvpn_address_t addr;
				int r = chipvpn_socket_read(config->sock, packet, sizeof(chipvpn_packet_t) + CHIPVPN_MTU, &addr);
				if(r > 0) {
					switch(packet_header->type) {
						case 0:
						case 1: {
							for(ListNode *p = list_begin(&config->peers); p != list_end(&config->peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								if(ntohl(packet_header->id) == peer->id) {
									peer->address = addr;
									chipvpn_log("connected to peer %i", peer->id);

									if(packet_header->type == 0) {
										packet_header->type = 1;
										chipvpn_socket_write(config->sock, packet, sizeof(chipvpn_packet_t), &addr);
									}
									break;
								}
							}
						}
						break;
						case 2: {
							int s = r - sizeof(chipvpn_packet_t);
							chipvpn_crypto_xcrypt(packet_data, s);

							ip_packet_t *ip = (ip_packet_t*)packet_data;

							for(ListNode *p = list_begin(&config->peers); p != list_end(&config->peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								chipvpn_address_t src = {
									.ip = ip->src_addr
								};

								if(chipvpn_address_cidr_match(&src, &peer->allow)) {
									chipvpn_tun_write(config->tun, packet_data, s);
									tun_can_write = 0;
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
	if(config->flag & CHIPVPN_DEVICE_POSTDOWN) {
		if(system(config->postdown) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}

	chipvpn_device_free(config);
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