#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "peer.h"
#include "config.h"

char *chipvpn_config_read_file(const char *file) {
	FILE *infp = fopen(file, "rb");
	if(!infp) {
		return NULL;
	}
	fseek(infp, 0, SEEK_END);
	long fsize = ftell(infp);
	char *p = malloc(fsize + 1);
	fseek(infp, 0, SEEK_SET);

	if(fread((char*)p, 1, fsize, infp)) {}

	fclose(infp);
	*(p + fsize) = '\0';

	return p;
}

void chipvpn_config_load(chipvpn_config_t *config, char *file) {
	config->flag = 0;
	list_clear(&config->peers);

	char *data = chipvpn_config_read_file(file);

	if(!data) {
		printf("unable to load config\n");
		exit(0);
	}

	chipvpn_config_section_e section = CONFIG_SECTION_NONE;

	char *line = strtok(data, "\n");
	while(line) {
		if(strcmp(line, "[interface]") == 0) {
			section = CONFIG_SECTION_INTERFACE;
			line = strtok(NULL, "\n");
			continue;
		}

		if(strcmp(line, "[peer]") == 0) {
			section = CONFIG_SECTION_PEER;
			line = strtok(NULL, "\n");

			chipvpn_peer_t *peer = malloc(sizeof(chipvpn_peer_t));
			list_insert(list_end(&config->peers), peer);
			continue;
		}

		char key[256], value[256];
		if(sscanf(line, "%128[^=]=%128[^\n]", key, value) == 2) {
			switch(section) {
				case CONFIG_SECTION_INTERFACE: {
					if(strcmp(key, "bind") == 0) {
						char ip[24];
						int port;
						if(sscanf(value, "%16[^:]:%i", ip, &port) == 2) {
							chipvpn_address_set_ip(&config->bind, ip);
							config->bind.port = port;
							config->flag |= CHIPVPN_DEVICE_BIND;
						}
					}

					if(strcmp(key, "address") == 0) {
						char ip[24];
						int prefix;
						if(sscanf(value, "%16[^/]/%i", ip, &prefix) == 2) {
							chipvpn_address_set_ip(&config->address, ip);
							config->address.prefix = prefix;
						}
					}

					if(strcmp(key, "postup") == 0) {
						strcpy(config->postup, value);
						config->flag |= CHIPVPN_DEVICE_POSTUP;
					}

					if(strcmp(key, "postdown") == 0) {
						strcpy(config->postdown, value);
						config->flag |= CHIPVPN_DEVICE_POSTDOWN;
					}
				}
				break;
				case CONFIG_SECTION_PEER: {
					chipvpn_peer_t *peer = (chipvpn_peer_t*)list_back(&config->peers);
					if(strcmp(key, "id") == 0) {
						peer->id = atoi(value);
					}

					if(strcmp(key, "allow") == 0) {
						char ip[24];
						int prefix;
						if(sscanf(value, "%16[^/]/%i", ip, &prefix) == 2) {
							chipvpn_address_set_ip(&peer->allow, ip);
							peer->allow.prefix = prefix;
						}
					}

					if(strcmp(key, "endpoint") == 0) {
						char ip[24];
						int port;
						if(sscanf(value, "%16[^:]:%i", ip, &port) == 2) {
							chipvpn_address_set_ip(&peer->endpoint, ip);
							peer->endpoint.port = port;
							peer->connect = true;
						}
					}
				}
				break;
				default: {
					printf("invalid section\n");
					exit(0);
				}
				break;
			}
		}

		line = strtok(NULL, "\n");
	}

	free(data);
}