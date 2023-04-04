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
#include "tun.h"

bool quit = false;

chipvpn_tun_t    *tun  = NULL;
chipvpn_socket_t *sock = NULL;

void chipvpn_setup(bool server) {
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, chipvpn_exit);
	signal(SIGQUIT, chipvpn_exit);
	signal(SIGTERM, chipvpn_exit);
	signal(SIGHUP, chipvpn_exit);

	chipvpn_log("ChipVPN UDP v1.0");

	chipvpn_init(server);
	chipvpn_loop();
	chipvpn_cleanup();
}

void chipvpn_init(bool server) {
	tun = chipvpn_tun_create(NULL);
	if(!tun) {
		chipvpn_error("unable to create tun device");
	}

	sock = chipvpn_socket_create();
	if(sock < 0) {
		chipvpn_error("socket creation failed");
	}

	if(server) {
		struct sockaddr_in servaddr;
		memset(&servaddr, 0, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = INADDR_ANY;
		servaddr.sin_port = htons(1332);

		if(bind(sock->fd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
			chipvpn_error("socket bind failed");
		}

		struct in_addr subnet, gateway;

		inet_aton("255.255.255.0", &subnet);
		inet_aton("10.0.2.1", &gateway);

		chipvpn_tun_setip(tun, gateway, subnet, CHIPVPN_MTU, 2000);
		chipvpn_tun_ifup(tun);
	} else {
		struct in_addr subnet, gateway;

		inet_aton("255.255.255.0", &subnet);
		inet_aton("10.0.2.2", &gateway);

		chipvpn_tun_setip(tun, gateway, subnet, CHIPVPN_MTU, 2000);
		chipvpn_tun_ifup(tun);
	}
}

void chipvpn_loop() {
	struct sockaddr_in cliaddr;
	memset(&cliaddr, 0, sizeof(cliaddr));
	cliaddr.sin_family = AF_INET;
	cliaddr.sin_addr.s_addr = inet_addr("3.0.7.3");
	cliaddr.sin_port = htons(1332);

	int len = sizeof(cliaddr);

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
					chipvpn_crypto_xcrypt(buf, r);
					sendto(sock->fd, buf, r, MSG_CONFIRM, (struct sockaddr*)&cliaddr, sizeof(cliaddr));
					sock_can_write = 0;
				}
				tun_can_read = 0;
			}

			if(sock_can_read && tun_can_write) {
				char buf[CHIPVPN_MTU];
				int r = recvfrom(sock->fd, buf, sizeof(buf), MSG_WAITALL, (struct sockaddr*)&cliaddr, (socklen_t*)&len);
				if(r > 0) {
					chipvpn_crypto_xcrypt(buf, r);
					write(tun->fd, buf, r);
					tun_can_write = 0;
				}
				sock_can_read = 0;
			}
		}
	}
}

void chipvpn_cleanup() {
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