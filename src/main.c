#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <time.h>
#include <stdlib.h>
#include "peer.h"
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
		fprintf(stderr, "config read failed\n");
		exit(1);
	}

	section_e section = DEVICE_SECTION;

	char line[8192];
	while(fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = 0;
		char key[32];
		char value[4096];
		if(sscanf(line, "%24[^:]:%1024[^\n]", key, value) == 2) {
			if(strcmp(key, "section") == 0 && strcmp(value, "device") == 0) {
				section = DEVICE_SECTION;
				continue;
			}

			if(section == DEVICE_SECTION && strcmp(key, "name") == 0) {
				char name[IFNAMSIZ + 1];
				if(sscanf(value, "%16[^\n]", name) == 1) {
					strcpy(config->name, name);
				}
			}

			if(section == DEVICE_SECTION && strcmp(key, "network") == 0) {
				char address[24];
				int prefix;
				if(sscanf(value, "%24[^/]/%i", address, &prefix) == 2) {
					if(!chipvpn_address_set_ip(&config->network, address)) {
						fprintf(stderr, "invalid address from config\n");
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
						fprintf(stderr, "invalid address from config\n");
						exit(1);
					}
					config->bind.port = port;
					config->is_bind = true;
				}
			}

			if(section == DEVICE_SECTION && strcmp(key, "xor") == 0) {
				char xorkey[1024];
				if(sscanf(value, "%1023s", xorkey) == 1) {
					strcpy(config->xorkey, xorkey);
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
		fprintf(stderr, "config read failed\n");
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
			if(strcmp(key, "section") == 0 && strcmp(value, "peer") == 0) {
				section = PEER_SECTION;

				chipvpn_peer_t *peer = chipvpn_peer_create();
				chipvpn_list_insert(chipvpn_list_end(&device->peers), peer);
				continue;
			}

			chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_back(&device->peers);

			if(section == PEER_SECTION && strcmp(key, "address") == 0) {
				char address[24];
				int port;
				if(sscanf(value, "%24[^:]:%i", address, &port) == 2) {
					chipvpn_peer_set_address(peer, address, port);
					peer->connect = true;
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

			if(memcmp(peer->key, peer1->key, sizeof(peer->key)) == 0) {
				chipvpn_list_remove(&peer->node);
				chipvpn_peer_free(peer);

				chipvpn_list_remove(&peer1->node);
				chipvpn_list_insert(chipvpn_list_end(&device->peers), peer1);
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
	printf("interrupt received\n");
	quit = 1;
}

int main(int argc, char const *argv[]) {
	/* code */
	srand(time(NULL));

	printf("chipvpn 1.7.4 rc5\n"); 

	if(!(argc > 1 && argv[1] != NULL)) {
		printf("config path required\n");
		exit(1);
	}

	int tun_fd = -1;
	if(argc > 2 && argv[2] != NULL) {
		tun_fd = atoi(argv[2]);
	}

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, terminate);
	signal(SIGQUIT, terminate);

	int mtime = 0;

	chipvpn_config_t config = {
		.name = "chipvpn",
		.mtu = 1400,
		.xorkey = "chipvpn",
		.sendbuf = 0,
		.recvbuf = 0
	};
	read_device_config(argv[1], &config);

	chipvpn_t *vpn = chipvpn_create(&config, tun_fd);
	if(!vpn) {
		fprintf(stderr, "unable to create vpn tunnel interface\n");
		exit(1);
	}

	if(file_mtime(argv[1]) > mtime) {
			printf("reload config\n");
			read_peer_config(argv[1], vpn->device);
			mtime = file_mtime(argv[1]);
		}

	while(!quit) {
		chipvpn_wait(vpn, 1000);
		chipvpn_service(vpn);

		if(file_mtime(argv[1]) > mtime) {
			mtime = file_mtime(argv[1]);
		}
	}

	printf("cleanup\n");

	chipvpn_cleanup(vpn);

	printf("shutting down\n"); 

	return 0;
}