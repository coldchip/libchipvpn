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
#include <ncurses.h>
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

	chipvpn_log("ChipVPN v2.1 beta 1");

	chipvpn_init(file);
	chipvpn_loop();
	chipvpn_cleanup();
}

void chipvpn_init(char *file) {
	initscr();
	noecho();
	curs_set(false);
	start_color();
	use_default_colors();
	init_pair(1, COLOR_GREEN, COLOR_BLACK);
	init_pair(2, COLOR_CYAN, COLOR_BLACK);
	init_pair(3, COLOR_WHITE, COLOR_BLACK);
	init_pair(4, COLOR_RED, COLOR_BLACK);
	init_pair(5, COLOR_MAGENTA, COLOR_BLACK);
	init_pair(6, COLOR_YELLOW, COLOR_BLACK);

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

		if(select(MAX(sock_fd, tun_fd) + 1, &rdset, &wdset, NULL, &tv) >= 0) {

			if(FD_ISSET(tun_fd, &rdset))  tun_can_read  = 1;
			if(FD_ISSET(tun_fd, &wdset))  tun_can_write = 1;
			if(FD_ISSET(sock_fd, &rdset)) sock_can_read  = 1;
			if(FD_ISSET(sock_fd, &wdset)) sock_can_write = 1;

			/* peer lifecycle service */
			if(sock_can_write && chipvpn_get_time() - chipvpn_last_update >= 1) {
				chipvpn_print_stats();
				for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
					chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
					if(peer->state == PEER_DISCONNECTED && peer->connect == true) {
						chipvpn_packet_auth_t auth = {};
						auth.header.type = 0;
						auth.id = htonl(peer->id);
						auth.ack = true;

						chipvpn_socket_write(device->sock, &auth, sizeof(auth), &peer->address);
						sock_can_write = 0;
					}
					if(peer->state == PEER_CONNECTED) {
						if(chipvpn_get_time() - peer->last_ping > 15) {
							peer->state = PEER_DISCONNECTED;
						} else {
							chipvpn_packet_ping_t ping = {};
							ping.header.type = 2;
							ping.id = htonl(peer->id);

							chipvpn_socket_write(device->sock, &ping, sizeof(ping), &peer->address);
							sock_can_write = 0;
						}
					}
				}
				chipvpn_last_update = chipvpn_get_time();
			}

			/* tun => sock */
			if(tun_can_read && sock_can_write) {
				char buf[device->mtu];
				int r = chipvpn_tun_read(device->tun, buf, sizeof(buf));
				tun_can_read = 0;
				if(r > 0) {
					for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
						chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

						ip_packet_t *ip = (ip_packet_t*)buf;
						chipvpn_address_t dst = {
							.ip = ip->dst_addr
						};

						if(chipvpn_address_cidr_match(&dst, &peer->allow) && peer->state == PEER_CONNECTED) {
							char buffer[sizeof(chipvpn_packet_data_t) + r];

							chipvpn_packet_data_t data = {};
							data.header.type = 1;

							chipvpn_crypto_xcrypt(buf, r);
							memcpy(buffer, &data, sizeof(chipvpn_packet_data_t));
							memcpy(buffer + sizeof(chipvpn_packet_data_t), buf, r);

							chipvpn_socket_write(device->sock, buffer, sizeof(chipvpn_packet_data_t) + r, &peer->address);
							sock_can_write = 0;
						}
					}
				}
			}

			/* sock => tun */
			if(sock_can_read && tun_can_write) {
				char buffer[sizeof(chipvpn_packet_t) + device->mtu];
				chipvpn_address_t addr;
				int r = chipvpn_socket_read(device->sock, buffer, sizeof(buffer), &addr);
				sock_can_read = 0;
				if(r > 0) {
					chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
					switch(header->type) {
						case 0: {
							if(r < sizeof(chipvpn_packet_auth_t)) {
								break;
							}

							chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

							for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								if(ntohl(packet->id) == peer->id) {
									peer->address = addr;
									peer->state = PEER_CONNECTED;
									peer->last_ping = chipvpn_get_time();

									if(packet->ack == true) {
										chipvpn_packet_auth_t auth = {};
										auth.header.type = 0;
										auth.id = packet->id;
										auth.ack = false;

										chipvpn_socket_write(device->sock, &auth, sizeof(chipvpn_packet_auth_t), &addr);
										sock_can_write = 0;
									}
									break;
								}
							}
						}
						break;
						case 1: {
							if(r < sizeof(chipvpn_packet_data_t)) {
								break;
							}

							chipvpn_packet_data_t *data = (chipvpn_packet_data_t*)buffer;
							char *buf = buffer + sizeof(chipvpn_packet_data_t);

							chipvpn_crypto_xcrypt(buf, r - sizeof(chipvpn_packet_data_t));

							for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								ip_packet_t *ip = (ip_packet_t*)buf;
								chipvpn_address_t src = {
									.ip = ip->src_addr
								};

								if(chipvpn_address_cidr_match(&src, &peer->allow) && peer->state == PEER_CONNECTED) {
									chipvpn_tun_write(device->tun, buf, r - sizeof(chipvpn_packet_data_t));
									tun_can_write = 0;
								}
							}
						}
						break;
						case 2: {
							if(r < sizeof(chipvpn_packet_ping_t)) {
								break;
							}

							chipvpn_packet_ping_t *packet = (chipvpn_packet_ping_t*)buffer;

							for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
								chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

								if(ntohl(packet->id) == peer->id) {
									peer->last_ping = chipvpn_get_time();
								}
							}
						}
						break;
					}
				}
			}
		}
	}
}

void chipvpn_print_stats() {
	struct in_addr ip = {};

	clear();

	bkgd(COLOR_PAIR(1));

	attron(COLOR_PAIR(2) | A_BOLD);
	printw("ColdChip ChipVPN v1.1 beta 1\n\n");
	attroff(COLOR_PAIR(2) | A_BOLD);

	attron(COLOR_PAIR(1) | A_BOLD);
	printw("interface: ");
	attroff(COLOR_PAIR(1) | A_BOLD);
	attron(COLOR_PAIR(3));
	printw("%s\n", device->tun->dev);
	attron(COLOR_PAIR(3));

	attron(COLOR_PAIR(3));
	printw("    network: ");
	attroff(COLOR_PAIR(3));
	attron(COLOR_PAIR(5));
	ip.s_addr = device->address.ip;
	printw("%s/%i\n", inet_ntoa(ip), device->address.prefix);
	attron(COLOR_PAIR(5));

	attron(COLOR_PAIR(3));
	printw("    mtu: ");
	attroff(COLOR_PAIR(3));
	attron(COLOR_PAIR(5));
	printw("%i\n", device->mtu);
	attron(COLOR_PAIR(5));

	if(device->flag & CHIPVPN_DEVICE_BIND) {
		attron(COLOR_PAIR(3));
		printw("    listen: ");
		attroff(COLOR_PAIR(3));
		attron(COLOR_PAIR(5));
		ip.s_addr = device->bind.ip;
		printw("%s:%i\n", inet_ntoa(ip), device->bind.port);
		attron(COLOR_PAIR(5));
	}

	printw("\n");

	for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		attron(COLOR_PAIR(6) | A_BOLD);
		printw("peer: ");
		attroff(COLOR_PAIR(6) | A_BOLD);
		attron(COLOR_PAIR(3));
		printw("%i\n", peer->id);
		attron(COLOR_PAIR(3));

		attron(COLOR_PAIR(3));
		printw("    status: ");
		attroff(COLOR_PAIR(3));
		if(peer->state == PEER_CONNECTED) {
			attron(COLOR_PAIR(1));
			printw("online\n");
			attron(COLOR_PAIR(1));
		} else {
			attron(COLOR_PAIR(4));
			printw("offline\n");
			attron(COLOR_PAIR(4));
		}
		
		if(peer->state == PEER_CONNECTED) {
			attron(COLOR_PAIR(3));
			printw("    endpoint: ");
			attroff(COLOR_PAIR(3));
			attron(COLOR_PAIR(5));
			ip.s_addr = peer->address.ip;
			printw("%s:%i\n", inet_ntoa(ip), peer->address.port);
			attron(COLOR_PAIR(5));

			attron(COLOR_PAIR(3));
			printw("    allowed ips: ");
			attroff(COLOR_PAIR(3));
			attron(COLOR_PAIR(5));
			ip.s_addr = peer->allow.ip;
			printw("%s/%i\n", inet_ntoa(ip), peer->allow.port);
			attron(COLOR_PAIR(5));
		}

		printw("\n");
	}

	refresh();
}

void chipvpn_cleanup() {
	if(device->flag & CHIPVPN_DEVICE_POSTDOWN) {
		if(system(device->postdown) == -1) {
			chipvpn_log("unable to execute postdown");
		}
	}

	chipvpn_device_free(device);

	endwin();
}

void chipvpn_exit(int type) {
	quit = true;
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