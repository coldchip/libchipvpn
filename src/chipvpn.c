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
#include "chipvpn.h"
#include "tun.h"

bool    quit = false;

VPNTun *tun = NULL;
int     sock = -1;

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

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		chipvpn_error("socket creation failed");
	}

	if(server) {
		struct sockaddr_in servaddr;
		memset(&servaddr, 0, sizeof(servaddr));
		servaddr.sin_family = AF_INET; // IPv4
		servaddr.sin_addr.s_addr = INADDR_ANY;
		servaddr.sin_port = htons(1332);

		if(bind(sock, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
			chipvpn_error("socket bind failed");
		}

		struct in_addr subnet, gateway;

		inet_aton("255.255.255.0", &subnet);
		inet_aton("10.0.2.1", &gateway);

		chipvpn_tun_setip(tun, gateway, subnet, 1500, 200000);
		chipvpn_tun_ifup(tun);
	} else {
		struct in_addr subnet, gateway;

		inet_aton("255.255.255.255", &subnet);
		inet_aton("10.0.2.2", &gateway);

		chipvpn_tun_setip(tun, gateway, subnet, 1500, 200000);
		chipvpn_tun_ifup(tun);
	}
}

void chipvpn_loop() {
	struct sockaddr_in cliaddr;
	int len;

	struct timeval tv;
	fd_set rdset, wdset;

	while(!quit) {
		tv.tv_sec = 0;
		tv.tv_usec = 250000;

		FD_ZERO(&rdset);
		FD_ZERO(&wdset);

		FD_SET(sock, &rdset);
		FD_SET(sock, &wdset);
		FD_SET(tun->fd, &rdset);
		FD_SET(tun->fd, &wdset);

		if(select(MAX(sock, tun->fd) + 1, &rdset, &wdset, NULL, &tv) >= 0) {
			if(FD_ISSET(sock, &rdset)) {
				char buf[8192];
				int r = recvfrom(sock, buf, sizeof(buf), MSG_WAITALL, (struct sockaddr*)&cliaddr, &len);
				write(tun->fd, buf, r);
			}

			if(FD_ISSET(tun->fd, &rdset)) {
				char buf[8192];
				int r = read(tun->fd, buf, sizeof(buf));
				sendto(sock, buf, r, MSG_CONFIRM, (struct sockaddr*)&cliaddr, len);
			}
		}
	}
}

void chipvpn_cleanup() {
	chipvpn_tun_free(tun);
	close(sock);
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