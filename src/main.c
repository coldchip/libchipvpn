#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <stdlib.h>
#include "util.h"
#include "peer.h"
#include "log.h"
#include "config.h"
#include "chipvpn.h"

int file_mtime(const char *path) {
	struct stat file_stat;
	int err = stat(path, &file_stat);
	if(err != 0) {
		return 0;
	}
	return file_stat.st_mtime;
}

volatile sig_atomic_t quit = 0;

void terminate(int type) {
	chipvpn_log_append("interrupt received\n");
	quit = 1;
}

int main(int argc, char const *argv[]) {
	srand(time(NULL));

	chipvpn_log_append("chipvpn %i alpha protocol %i\n", CHIPVPN_VERSION, CHIPVPN_PROTOCOL_VERSION); 

	if(!(argc > 1 && argv[1] != NULL)) {
		chipvpn_log_append("config path required\n");
		exit(1);
	}

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, terminate);
	signal(SIGQUIT, terminate);

	chipvpn_config_t config = {
		.ipc_bind.path = "/var/run/chipvpn.sock"
	};
	
	chipvpn_t *vpn = chipvpn_create(&config, -1);
	if(!vpn) {
		chipvpn_log_append("unable to create vpn tunnel interface\n");
		exit(1);
	}

	char *file = chipvpn_read_file(argv[1]);
	if(!file) {
		chipvpn_log_append("unable to open config %s\n", argv[1]);
		exit(1);
	}

	chipvpn_config_command(vpn, file);

	free(file);

	while(!quit) {
		chipvpn_poll(vpn, 250);
		chipvpn_service(vpn);
	}

	chipvpn_log_append("cleanup\n");

	chipvpn_cleanup(vpn);

	chipvpn_log_append("shutting down\n"); 

	return 0;
}