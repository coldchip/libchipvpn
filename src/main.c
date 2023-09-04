#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include "peer.h"
#include "chipvpn.h"

bool get_gateway(char *ip) {
	bool success = true;

	char cmd[] = "ip route show default | awk '/default/ {print $3}'";
	FILE* fp = popen(cmd, "r");

	if(fgets(ip, 16, fp) == NULL){
		success = false;
	}

	ip[15] = '\0';

	int i = 0;
	while((ip[i] >= '0' && ip[i] <= '9') || ip[i] == '.') {
		i++;
	}

	ip[i] = 0;

	pclose(fp);

	return success;
}

int add_route(char *src, uint8_t mask, char *dst) {
	char command[8192];

	sprintf(command, "ip route add %s/%i via %s", src, mask, dst);
	int ret = system(command);
	printf("%s\n", command);
	return ret;
}

int del_route(char *src, uint8_t mask, char *dst) {
	char command[8192];

	sprintf(command, "ip route del %s/%i via %s", src, mask, dst);
	int ret = system(command);
	printf("%s\n", command);
	return ret;
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

int file_mtime(const char *path) {
	struct stat file_stat;
	int err = stat(path, &file_stat);
	if (err != 0) {
		return 0;
	}
	return file_stat.st_mtime;
}

typedef enum {
	DEVICE_SECTION,
	PEER_SECTION
} section_e;

void read_device_config(const char *path, chipvpn_device_t *device) {
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
		if(sscanf(line, "%24[^:]:%s", key, value) == 2) {
			if(strcmp(key, "section") == 0 && strcmp(value, "device") == 0) {
				section = DEVICE_SECTION;
				continue;
			}

			if(section == DEVICE_SECTION && strcmp(key, "network") == 0) {
				char address[24];
				int prefix;
				if(sscanf(value, "%24[^/]/%i", address, &prefix) == 2) {
					chipvpn_device_set_address(device, address, prefix);
				}
			}

			if(section == DEVICE_SECTION && strcmp(key, "mtu") == 0) {
				int mtu;
				if(sscanf(value, "%i", &mtu) == 1) {
					chipvpn_device_set_mtu(device, mtu);
				}
			}
		}
	}

	fclose(fp);

	chipvpn_device_set_enabled(device);
}

void read_peer_config(const char *path, chipvpn_device_t *device) {
	FILE *fp = fopen(path, "r");
	if(!fp) {
		fprintf(stderr, "config read failed\n");
		exit(1);
	}

	chipvpn_peer_t *peers = malloc(sizeof(char));

	int peer_index = 0;

	chipvpn_peer_t *peer = NULL;

	section_e section = DEVICE_SECTION;

	char line[8192];
	while(fgets(line, sizeof(line), fp)) {
		line[strcspn(line, "\n")] = 0;
		char key[32];
		char value[4096];
		if(sscanf(line, "%24[^:]:%s", key, value) == 2) {
			if(strcmp(key, "section") == 0 && strcmp(value, "peer") == 0) {
				section = PEER_SECTION;
				peers = realloc(peers, sizeof(chipvpn_peer_t) * ++peer_index);
				peer = &peers[peer_index - 1];
				chipvpn_peer_reset(peer);
				continue;
			}

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
		}
	}

	fclose(fp);

	for(chipvpn_peer_t *peer = peers; peer < &peers[peer_index]; ++peer) {
		chipvpn_peer_t *online = chipvpn_peer_get_by_key(device->peers, device->peer_count, peer->crypto.key);
		if(online) {
			memcpy(peer, online, sizeof(chipvpn_peer_t));
		}
	}

	memcpy(device->peers, peers, peer_index * sizeof(chipvpn_peer_t));

	free(peers);
}

volatile sig_atomic_t quit = 0;

void terminate(int type) {
	quit = 1;
}

int main(int argc, char const *argv[]) {
	/* code */

	printf("chipvpn 1.62\n"); 

	if(!(argc > 1 && argv[1] != NULL)) {
		printf("config path required\n");
		exit(1);
	}

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, terminate);
	signal(SIGQUIT, terminate);

	int mtime = 0;

	chipvpn_device_t *device = chipvpn_device_create(1);
	if(!device) {
		fprintf(stderr, "unable to create device\n");
		exit(1);
	}

	read_device_config(argv[1], device);

	chipvpn_t *vpn = NULL;
	if(argc > 2 && strcmp(argv[2], "server") == 0) {
		chipvpn_address_t bind;
		chipvpn_address_set_ip(&bind, "0.0.0.0");
		bind.port = 4433;
		vpn = chipvpn_create(device, &bind);
	} else {
		vpn = chipvpn_create(device, NULL);
	}

	if(!vpn) {
		fprintf(stderr, "unable to create vpn\n");
		exit(1);
	}

	// printf("adding routes\n");

	// char gateway[21];
	// if(get_gateway(gateway)) {
	// 	add_route("157.245.205.9", 32, gateway);
	// 	add_route("0.0.0.0", 1, "10.128.0.1");
	// 	add_route("128.0.0.0", 1, "10.128.0.1");
	// }

	while(!quit) {
		chipvpn_wait(vpn, 100);
		chipvpn_service(vpn);

		if(file_mtime(argv[1]) > mtime) {
			printf("reload config\n");
			read_peer_config(argv[1], device);
			mtime = file_mtime(argv[1]);
		}
	}

	// printf("deleting routes\n");

	// del_route("157.245.205.9", 32, gateway);
	// del_route("0.0.0.0", 1, "10.128.0.1");
	// del_route("128.0.0.0", 1, "10.128.0.1");

	printf("cleanup\n");

	chipvpn_device_free(device);
	chipvpn_cleanup(vpn);

	printf("goodbye\n"); 

	return 0;
}