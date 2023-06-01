#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include "device.h"
#include "chipvpn.h"

bool quit = false;

void chipvpn_exit(int type) {
	quit = true;
}

int main(int argc, char const *argv[]) {
	if(argc > 1) {
		setbuf(stdout, 0);

		signal(SIGINT, chipvpn_exit);
		signal(SIGTERM, chipvpn_exit);

		#ifndef _WIN32
		signal(SIGPIPE, SIG_IGN);
		signal(SIGHUP, chipvpn_exit);
		signal(SIGQUIT, chipvpn_exit);
		#endif

		char *config = (char *)argv[1];

		uint64_t last_update = 0;
	
		chipvpn_t *chipvpn = chipvpn_init(config);
		while(!quit) {
			if(chipvpn_get_time() - last_update >= 1) {
				chipvpn_print_stats(chipvpn);
				chipvpn_device_reload_config(chipvpn->device, config);
				last_update = chipvpn_get_time();
			}
			chipvpn_loop(chipvpn);
		}
		chipvpn_cleanup(chipvpn);
	} else {
		chipvpn_error("usage: %s config.ini", (char *)argv[0]);
	}

	return 0;
}