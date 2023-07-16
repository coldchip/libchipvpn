#include <string.h>
#include <stdbool.h>
#include <signal.h>
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
			chipvpn_loop(vpn, (char *)argv[1]);
		}
		chipvpn_cleanup(vpn);
    } else {
        chipvpn_error("usage: %s config.ini", (char *)argv[0]);
    }

    return 0;
}