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
#include "crypto.h"
#include "chipvpn.h"
#include "socket.h"
#include "packet.h"
#include "address.h"
#include "config.h"
#include "peer.h"
#include "tun.h"

bool quit = false;

chipvpn_config_t *config = NULL;
List peers;

chipvpn_tun_t    *tun  = NULL;
chipvpn_socket_t *sock = NULL;

void chipvpn_setup(chipvpn_config_t *cfg) {
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, chipvpn_exit);
	signal(SIGQUIT, chipvpn_exit);
	signal(SIGTERM, chipvpn_exit);
	signal(SIGHUP, chipvpn_exit);

	chipvpn_log("ChipVPN UDP v1.0");

	config = cfg;

	chipvpn_init();
	chipvpn_loop();
	chipvpn_cleanup();
}

void chipvpn_init() {
	list_clear(&peers);

	while(!list_empty(&config->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)list_remove(list_begin(&config->peers));
		list_insert(list_end(&peers), peer);
	}

	tun = chipvpn_tun_create(NULL);
	if(!tun) {
		chipvpn_error("unable to create tun device");
	}

	sock = chipvpn_socket_create();
	if(sock < 0) {
		chipvpn_error("socket creation failed");
	}

	if(config->has_bind) {
		if(!chipvpn_socket_bind(sock, &config->bind)) {
			chipvpn_error("socket bind failed");
		}
	}

	chipvpn_tun_setip(tun, &config->address, CHIPVPN_MTU, 2000);
	chipvpn_tun_ifup(tun);

	for(ListNode *p = list_begin(&peers); p != list_end(&peers); p = list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		if(peer->connect == true) {
			chipvpn_packet_t packet;
			packet.type = 0;
			packet.id = htonl(peer->id);

			chipvpn_socket_write(sock, &packet, sizeof(chipvpn_packet_t), &peer->endpoint);
		}
	}

	if(config->has_postup) {
		system(config->postup);
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

	while(!quit) {
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		FD_CLR(tun->fd, &rdset);
		FD_CLR(tun->fd, &wdset);
		FD_CLR(sock->fd, &wdset);
		FD_CLR(sock->fd, &rdset);

		if(!tun_can_read)   FD_SET(tun->fd, &rdset);
		if(!tun_can_write)  FD_SET(tun->fd, &wdset);
		if(!sock_can_write) FD_SET(sock->fd, &wdset);
		if(!sock_can_read)  FD_SET(sock->fd, &rdset);

		if(select(MAX(sock->fd, tun->fd) + 1, &rdset, &wdset, NULL, &tv) >= 0) {

			if(FD_ISSET(tun->fd, &rdset))  tun_can_read  = 1;
			if(FD_ISSET(tun->fd, &wdset))  tun_can_write = 1;
			if(FD_ISSET(sock->fd, &rdset)) sock_can_read  = 1;
			if(FD_ISSET(sock->fd, &wdset)) sock_can_write = 1;

			if(tun_can_read && sock_can_write) {
				char buf[CHIPVPN_MTU];
				int r = read(tun->fd, buf, sizeof(buf));
				if(r > 0) {
					ip_packet_t *ip = (ip_packet_t*)buf;

					for(ListNode *p = list_begin(&peers); p != list_end(&peers); p = list_next(p)) {
						chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

						chipvpn_address_t dst = {
							.ip = ip->dst_addr
						};

						if(chipvpn_address_cidr_match(&dst, &peer->allow)) {

							chipvpn_crypto_xcrypt(buf, r);

							packet_header->type = 2;
							memcpy(packet_data, buf, r);

							chipvpn_socket_write(sock, packet, sizeof(chipvpn_packet_t) + r, &peer->address);
							sock_can_write = 0;
						}
					}
				}
				tun_can_read = 0;
			}

			if(sock_can_read && tun_can_write) {
				chipvpn_address_t addr;
				int r = chipvpn_socket_read(sock, packet, sizeof(chipvpn_packet_t) + CHIPVPN_MTU, &addr);
				if(r > 0) {
					switch(packet_header->type) {
						case 0:
						case 1: {
							for(ListNode *p = list_begin(&peers); p != list_end(&peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								if(ntohl(packet_header->id) == peer->id) {
									peer->address = addr;
									chipvpn_log("peer %p connected, port %i", peer, addr.port);

									if(packet_header->type == 0) {
										packet_header->type = 1;
										chipvpn_socket_write(sock, packet, sizeof(chipvpn_packet_t), &addr);
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

							for(ListNode *p = list_begin(&peers); p != list_end(&peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								chipvpn_address_t src = {
									.ip = ip->src_addr
								};

								if(chipvpn_address_cidr_match(&src, &peer->allow)) {
									write(tun->fd, packet_data, s);
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
	if(config->has_postdown) {
		system(config->postdown);
	}

	while(!list_empty(&peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)list_remove(list_begin(&peers));
		free(peer);
	}

	chipvpn_tun_free(tun);
	chipvpn_socket_free(sock);
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