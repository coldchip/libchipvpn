#include <signal.h>
#include <string.h>
#include "peer.h"
#include "chipvpn.h"

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

void read_config(const char *path) {
	FILE *fp = fopen(path, "r");
	if(!fp) {
		fprintf(stderr, "config read failed\n");
		exit(1);
	}

	char line[8192];

	while(fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = 0;

		printf("%s\n", line);
	}

	fclose(fp);
}

volatile sig_atomic_t quit = 0;

void terminate(int type) {
	quit = 1;
}

int main(int argc, char const *argv[]) {
	/* code */

	printf("chipvpn 1.2\n"); 

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, terminate);
	signal(SIGQUIT, terminate);



	chipvpn_device_t *device = chipvpn_device_create();
	if(!device) {
		fprintf(stderr, "unable to create device\n");
		exit(1);
	}
	chipvpn_device_set_address(device, "10.128.0.4", 16);
	chipvpn_device_set_mtu(device, 1400);
	chipvpn_device_set_name(device, "chipvpn");
	chipvpn_device_set_enabled(device);

	chipvpn_peer_t *peer = chipvpn_peer_create();
	if(!peer) {
		fprintf(stderr, "unable to create peer\n");
		exit(1);
	}
	chipvpn_peer_set_endpoint(peer, "157.245.205.9", 443);
	chipvpn_peer_set_allow(peer, "0.0.0.0", 0);
	chipvpn_peer_set_key(peer, "DQpMnJgkndkrD8wVxd5noIEcJ1wWjS6bJtL6kFUoeBHclqnS0UaPjvs5UPZB0Q2n");
	chipvpn_peer_insert(device, peer);



	chipvpn_t *vpn = chipvpn_create(device, NULL);
	if(!vpn) {
		fprintf(stderr, "unable to create vpn\n");
		exit(1);
	}

	chipvpn_peer_state_e current_state = PEER_DISCONNECTED;

	while(!quit) {
		chipvpn_wait(vpn);
		chipvpn_service(vpn);

		// read_config("config.txt");

		if(peer->state == PEER_DISCONNECTED) {
			chipvpn_peer_connect(peer, 10);
		}

		// printf("%li %li\n", peer->tx, peer->rx);

		if(current_state != peer->state) {
			switch(peer->state) {
				case PEER_CONNECTED: {
					printf("current status: peer_connected\n");
				}
				break;
				case PEER_DISCONNECTED: {
					printf("current status: peer_disconnected\n");
				}
				break;
			}
			current_state = peer->state;
		}
	}

	printf("cleanup\n");

	chipvpn_peer_disconnect(peer, 10);

	chipvpn_device_free(device);
	chipvpn_cleanup(vpn);

	return 0;
}