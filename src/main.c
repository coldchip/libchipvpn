#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include "chipvpn.h"

bool quit = false;

void terminate(int type) {
	quit = true;
}

int main(int argc, char const *argv[]) {
    if(argc > 1) {
        signal(SIGINT, terminate);
		signal(SIGTERM, terminate);

		#ifndef _WIN32
		signal(SIGPIPE, SIG_IGN);
		signal(SIGHUP, terminate);
		signal(SIGQUIT, terminate);
		#endif

		chipvpn_t *vpn = chipvpn_init((char *)argv[1]);
		while(!quit) {
			chipvpn_service(vpn, 0);
		}
		chipvpn_cleanup(vpn);
    } else {
        printf("usage: %s config.ini\n", (char *)argv[0]);
        exit(1);
    }

    return 0;
}