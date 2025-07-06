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
#include "chipvpn.h"

int file_mtime(const char *path) {
	struct stat file_stat;
	int err = stat(path, &file_stat);
	if(err != 0) {
		return 0;
	}
	return file_stat.st_mtime;
}

typedef enum {
	DEVICE_SECTION,
	PEER_SECTION
} section_e;

void read_device_config(const char *path, chipvpn_config_t *config) {
	FILE *fp = fopen(path, "r");
	if(!fp) {
		chipvpn_log_append("config read failed\n");
		exit(1);
	}

	section_e section = DEVICE_SECTION;

	char line[8192];
	while(fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = 0;
		char key[32];
		char value[4096];
		if(sscanf(line, "%24[^:]:%1024[^\n]", key, value) == 2) {
			// includes
			if(strcmp(key, "include") == 0) {
				read_device_config(value, config);
				continue;
			}

			if(strcmp(key, "section") == 0 && strcmp(value, "device") == 0) {
				section = DEVICE_SECTION;
				continue;
			}

			if(section == DEVICE_SECTION && strcmp(key, "name") == 0) {
				char name[IF_NAMESIZE + 1];
				if(sscanf(value, "%16[^\n]", name) == 1) {
					strcpy(config->name, name);
				}
			}

			if(section == DEVICE_SECTION && strcmp(key, "network") == 0) {
				char address[24];
				int prefix;
				if(sscanf(value, "%24[^/]/%i", address, &prefix) == 2) {
					if(!chipvpn_address_set_ip(&config->network, address)) {
						chipvpn_log_append("invalid address from config\n");
						exit(1);
					}
					config->network.prefix = prefix;
				}
			}

			if(section == DEVICE_SECTION && strcmp(key, "mtu") == 0) {
				int mtu;
				if(sscanf(value, "%i", &mtu) == 1) {
					config->mtu = mtu;
				}
			}

			if(section == DEVICE_SECTION && strcmp(key, "bind") == 0) {
				char address[24];
				int port;
				if(sscanf(value, "%24[^:]:%i", address, &port) == 2) {
					if(!chipvpn_address_set_ip(&config->bind, address)) {
						chipvpn_log_append("invalid address from config\n");
						exit(1);
					}
					config->bind.port = port;
					config->is_bind = true;
				}
			}

			if(section == DEVICE_SECTION && strcmp(key, "sendbuf") == 0) {
				int sendbuf;
				if(sscanf(value, "%i", &sendbuf) == 1) {
					config->sendbuf = sendbuf;
				}
			}

			if(section == DEVICE_SECTION && strcmp(key, "recvbuf") == 0) {
				int recvbuf;
				if(sscanf(value, "%i", &recvbuf) == 1) {
					config->recvbuf = recvbuf;
				}
			}
		}
	}

	fclose(fp);
}

void read_peer_config(const char *path, chipvpn_device_t *device) {
	FILE *fp = fopen(path, "r");
	if(!fp) {
		chipvpn_log_append("config read failed\n");
		exit(1);
	}

	chipvpn_list_t temp;
	chipvpn_list_clear(&temp);

	// move every peer from device to temp
	while(!chipvpn_list_empty(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&device->peers));
		chipvpn_list_insert(chipvpn_list_end(&temp), peer);
	}

	// clear device peers
	chipvpn_list_clear(&device->peers);

	section_e section = DEVICE_SECTION;

	char line[8192];
	while(fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = 0;
		char key[32];
		char value[4096];
		if(sscanf(line, "%24[^:]:%1024[^\n]", key, value) == 2) {
			// includes
			if(strcmp(key, "include") == 0) {
				read_peer_config(value, device);
				continue;
			}

			if(strcmp(key, "section") == 0 && strcmp(value, "peer") == 0) {
				section = PEER_SECTION;

				chipvpn_peer_t *peer = chipvpn_peer_create();
				chipvpn_list_insert(chipvpn_list_end(&device->peers), peer);
				continue;
			}

			chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_back(&device->peers);

			if(section == PEER_SECTION && strcmp(key, "address") == 0) {
				char address[512];
				int port;
				if(sscanf(value, "%512[^:]:%i", address, &port) == 2) {
					chipvpn_peer_set_address(peer, address, port);
					peer->config.connect = true;
				}
			}

			if(section == PEER_SECTION && strcmp(key, "allow") == 0) {
				char address[24];
				int prefix;
				if(sscanf(value, "%24[^/]/%i", address, &prefix) == 2) {
					chipvpn_peer_set_allow(peer, address, prefix);
				}
			}

			if(section == PEER_SECTION && strcmp(key, "key") == 0) {
				char key[1024];
				if(sscanf(value, "%1023s", key) == 1) {
					chipvpn_peer_set_key(peer, key);
				}
			}

			if(section == PEER_SECTION && strcmp(key, "onconnect") == 0) {
				chipvpn_peer_set_onconnect(peer, value);
			}

			if(section == PEER_SECTION && strcmp(key, "onping") == 0) {
				chipvpn_peer_set_onping(peer, value);
			}

			if(section == PEER_SECTION && strcmp(key, "ondisconnect") == 0) {
				chipvpn_peer_set_ondisconnect(peer, value);
			}
		}
	}

	fclose(fp);

	// move connected peers from temp to device
	chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers);
	while(p != chipvpn_list_end(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		p = chipvpn_list_next(p);

		chipvpn_list_node_t *t = chipvpn_list_begin(&temp);
		while(t != chipvpn_list_end(&temp)) {
			chipvpn_peer_t *peer1 = (chipvpn_peer_t*)t;
			t = chipvpn_list_next(t);

			if(memcmp(peer->config.key, peer1->config.key, sizeof(peer->config.key)) == 0) {
				chipvpn_list_remove(&peer->node);
				chipvpn_peer_free(peer);

				chipvpn_list_remove(&peer1->node);
				chipvpn_list_insert(chipvpn_list_end(&device->peers), peer1);

				break;
			}
		}
	}

	// remove deleted peers from temp
	while(!chipvpn_list_empty(&temp)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&temp));
		chipvpn_peer_free(peer);
	}
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
		.name = "chipvpn",
		.mtu = 1420,
		.sendbuf = 0,
		.recvbuf = 0,
	};
	
	read_device_config(argv[1], &config);

	chipvpn_t *vpn = chipvpn_create(&config, -1);
	if(!vpn) {
		chipvpn_log_append("unable to create vpn tunnel interface\n");
		exit(1);
	}

	uint64_t last_check = 0;

	while(!quit) {
		chipvpn_poll(vpn, 250);
		chipvpn_service(vpn);

		if(chipvpn_get_time() - last_check > 2000) {
			read_peer_config(argv[1], vpn->device);
			last_check = chipvpn_get_time();
		}
	}

	chipvpn_log_append("cleanup\n");

	chipvpn_cleanup(vpn);

	chipvpn_log_append("shutting down\n"); 

	return 0;
}