#include <stdio.h>
#include <string.h>
#include "peer.h"
#include "device.h"
#include "config.h"
#include "util.h"

chipvpn_command_section_e section;

void chipvpn_config_command(chipvpn_t *vpn, char *command) {
	char line[8192];
	while(chipvpn_sgets(line, sizeof(line), (const char **)&command)) {
		line[strcspn(line, "\n")] = 0;
		char key[32];
		char value[4096];
		if(sscanf(line, "%24[^:]:%1024[^\n]", key, value) == 2) {
			if(strcmp(key, "section") == 0 && strcmp(value, "device") == 0) {
				section = COMMAND_DEVICE_SECTION;
				continue;
			}

			if(strcmp(key, "section") == 0 && strcmp(value, "peer") == 0) {
				section = COMMAND_PEER_SECTION;

				chipvpn_peer_t *peer = chipvpn_peer_create();
				chipvpn_list_insert(chipvpn_list_end(&vpn->device->peers), peer);
				continue;
			}

			if(section == COMMAND_DEVICE_SECTION && strcmp(key, "name") == 0) {
				char name[IF_NAMESIZE + 1];
				if(sscanf(value, "%16[^\n]", name) == 1) {
					if(!chipvpn_device_set_name(vpn->device, name)) {
						return;
					}
				}
			}

			if(section == COMMAND_DEVICE_SECTION && strcmp(key, "network") == 0) {
				char address[24];
				int prefix;
				if(sscanf(value, "%24[^/]/%i", address, &prefix) == 2) {
					chipvpn_address_t network;
					if(!chipvpn_address_set_ip(&network, address)) {
						return;
					}
					network.prefix = prefix;
					if(!chipvpn_device_set_address(vpn->device, &network)) {
						return;
					}
				}
			}

			if(section == COMMAND_DEVICE_SECTION && strcmp(key, "mtu") == 0) {
				int mtu;
				if(sscanf(value, "%i", &mtu) == 1) {
					if(!chipvpn_device_set_mtu(vpn->device, mtu)) {
						return;
					}
				}
			}

			if(section == COMMAND_DEVICE_SECTION && strcmp(key, "bind") == 0) {
				char address[24];
				int port;
				if(sscanf(value, "%24[^:]:%i", address, &port) == 2) {
					chipvpn_address_t bind;
					if(!chipvpn_address_set_ip(&bind, address)) {
						return;
					}
					bind.port = port;
					if(!chipvpn_socket_bind(vpn->socket, &bind)) {
						return;
					}
				}
			}

			if(section == COMMAND_DEVICE_SECTION && strcmp(key, "sendbuf") == 0) {
				int sendbuf;
				if(sscanf(value, "%i", &sendbuf) == 1) {
					chipvpn_socket_set_sendbuf(vpn->socket, sendbuf);
				}
			}

			if(section == COMMAND_DEVICE_SECTION && strcmp(key, "recvbuf") == 0) {
				int recvbuf;
				if(sscanf(value, "%i", &recvbuf) == 1) {
					chipvpn_socket_set_recvbuf(vpn->socket, recvbuf);
				}
			}

			if(section == COMMAND_DEVICE_SECTION && strcmp(key, "ifup") == 0) {
				chipvpn_device_set_enabled(vpn->device);
			}

			if(section == COMMAND_DEVICE_SECTION && strcmp(key, "ifdown") == 0) {
				chipvpn_device_set_disabled(vpn->device);
			}

			if(strcmp(key, "clear") == 0) {
				while(!chipvpn_list_empty(&vpn->device->peers)) {
					chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&vpn->device->peers));
					chipvpn_peer_free(peer);
				}
			}

			chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_back(&vpn->device->peers);

			if(section == COMMAND_PEER_SECTION && strcmp(key, "address") == 0) {
				char address[512];
				int port;
				if(sscanf(value, "%512[^:]:%i", address, &port) == 2) {
					chipvpn_peer_set_address(peer, address, port);
					peer->config.connect = true;
				}
			}

			if(section == COMMAND_PEER_SECTION && strcmp(key, "allow") == 0) {
				char address[24];
				int prefix;
				if(sscanf(value, "%24[^/]/%i", address, &prefix) == 2) {
					chipvpn_peer_set_allow(peer, address, prefix);
				}
			}

			if(section == COMMAND_PEER_SECTION && strcmp(key, "key") == 0) {
				char key[1024];
				if(sscanf(value, "%1023s", key) == 1) {
					chipvpn_peer_set_key(peer, key);
				}
			}

			if(section == COMMAND_PEER_SECTION && strcmp(key, "onconnect") == 0) {
				chipvpn_peer_set_onconnect(peer, value);
			}

			if(section == COMMAND_PEER_SECTION && strcmp(key, "onping") == 0) {
				chipvpn_peer_set_onping(peer, value);
			}

			if(section == COMMAND_PEER_SECTION && strcmp(key, "ondisconnect") == 0) {
				chipvpn_peer_set_ondisconnect(peer, value);
			}
		}
	}
}