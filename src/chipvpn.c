#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <ncurses.h>
#include <sodium.h>
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

chipvpn_tun_t    *tun = NULL;
chipvpn_socket_t *sock = NULL;

void chipvpn_setup(char *config) {
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, chipvpn_exit);
	signal(SIGQUIT, chipvpn_exit);
	signal(SIGTERM, chipvpn_exit);
	signal(SIGHUP, chipvpn_exit);

	chipvpn_init(config);
	chipvpn_loop(config);
	chipvpn_cleanup();
}

void chipvpn_init(char *config) {
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

	if(sodium_init() == -1) {
		chipvpn_error("unable to initialize libsodium crypto");
	}

	device = chipvpn_device_create(config);
	if(!device) {
		chipvpn_error("unable to create config");
	}

	tun = chipvpn_tun_create(device->name);
	if(!tun) {
		chipvpn_error("unable to create tunnel interface");
	}

	sock = chipvpn_socket_create();
	if(!sock) {
		chipvpn_error("unable to create socket");
	}

	chipvpn_tun_setip(tun, &device->address, device->mtu, device->qlen);
	chipvpn_tun_ifup(tun);

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

	int tun_fd  = tun->fd;
	int sock_fd = sock->fd;

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
				chipvpn_device_reload_config(device, config);
				chipvpn_print_stats();
				for(ListNode *p = list_begin(&device->peers); p != list_end(&device->peers); p = list_next(p)) {
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
		}
	}
}

void chipvpn_print_stats() {
	struct in_addr ip = {};

	clear();

	bkgd(COLOR_PAIR(1));

	attron(COLOR_PAIR(2) | A_BOLD);
	printw("ColdChip ChipVPN v1.1 beta 5\n\n");
	attroff(COLOR_PAIR(2) | A_BOLD);

	attron(COLOR_PAIR(1) | A_BOLD);
	printw("interface: ");
	attroff(COLOR_PAIR(1) | A_BOLD);
	attron(COLOR_PAIR(3));
	printw("%s\n", tun->dev);
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

	attron(COLOR_PAIR(3));
	printw("    txqueuelen: ");
	attroff(COLOR_PAIR(3));
	attron(COLOR_PAIR(5));
	printw("%i\n", device->qlen);
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
		printw("session::%u\n", peer->sender_id);
		attron(COLOR_PAIR(3));

		attron(COLOR_PAIR(3));
		printw("    status: ");
		attroff(COLOR_PAIR(3));
		if(peer->state == PEER_CONNECTED) {
			attron(COLOR_PAIR(1));
			printw("online\n");
			attron(COLOR_PAIR(1));
		} else {
			if(peer->connect) {
				attron(COLOR_PAIR(2));
				printw("connecting\n");
				attron(COLOR_PAIR(2));
			} else {
				attron(COLOR_PAIR(4));
				printw("offline\n");
				attron(COLOR_PAIR(4));
			}
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
			printw("%s/%i\n", inet_ntoa(ip), peer->allow.prefix);
			attron(COLOR_PAIR(5));

			attron(COLOR_PAIR(3));
			printw("    encryption: ");
			attroff(COLOR_PAIR(3));
			attron(COLOR_PAIR(5));
			printw("xchacha20\n");
			attron(COLOR_PAIR(5));

			attron(COLOR_PAIR(3));
			printw("    bandwidth: ");
			attroff(COLOR_PAIR(3));
			attron(COLOR_PAIR(5));
			char c_tx[64];
			char c_rx[64];
			strcpy(c_tx, chipvpn_format_bytes(peer->tx));
			strcpy(c_rx, chipvpn_format_bytes(peer->rx));
			printw("%s received, %s sent\n", c_rx, c_tx);
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

	chipvpn_tun_free(tun);
	chipvpn_socket_free(sock);

	chipvpn_device_free(device);

	endwin();
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