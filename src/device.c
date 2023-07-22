#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "peer.h"
#include "device.h"
#include "chipvpn.h"
#include "ini.h"

chipvpn_device_t *chipvpn_device_create(char *file) {
	chipvpn_device_t *device = malloc(sizeof(chipvpn_device_t));
	if(!device) {
		return NULL;
	}

	chipvpn_list_clear(&device->peers);
	device->flag = 0;
	device->postup = NULL;
	device->postdown = NULL;
	device->name = NULL;
	device->mtu = 1420;

	if(file) {
		if(!chipvpn_device_reload_config(device, file)) {
			return NULL;
		}
	}

	return device;
}

bool chipvpn_device_reload_config(chipvpn_device_t *device, char *file) {
	chipvpn_list_t temp;
	chipvpn_list_clear(&temp);

	// move every peer from device to temp
	while(!chipvpn_list_empty(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&device->peers));
		chipvpn_list_insert(chipvpn_list_end(&temp), peer);
	}

	// clear device peers
	chipvpn_list_clear(&device->peers);

	// reload config
	if(ini_parse(file, chipvpn_device_parse_handler, device) < 0) {
		return false;
	}

	// move connected peers from temp to device
	chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers);
	while(p != chipvpn_list_end(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		p = chipvpn_list_next(p);

		chipvpn_list_node_t *t = chipvpn_list_begin(&temp);
		while(t != chipvpn_list_end(&temp)) {
			chipvpn_peer_t *peer1 = (chipvpn_peer_t*)t;
			t = chipvpn_list_next(t);

			if(memcmp(peer->crypto->key, peer1->crypto->key, sizeof(peer->crypto->key)) == 0) {
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

	return true;
}

int chipvpn_device_parse_handler(void* user, const char* section, const char* name, const char* value) {
	chipvpn_device_t* device = (chipvpn_device_t*)user;

	#define MATCH(s, n) strcasecmp(section, s) == 0 && strcasecmp(name, n) == 0

	if(name && value) {
		if(MATCH("interface", "bind")) {
			char ip[24];
			int port;
			if(sscanf(value, "%16[^:]:%i", ip, &port) == 2) {
				if(!chipvpn_address_set_ip(&device->bind, ip)) {
					return 0;
				}
				device->bind.port = port;
				device->flag |= CHIPVPN_DEVICE_BIND;
			}
		}

		if(MATCH("interface", "address")) {
			char ip[24];
			int prefix;
			if(sscanf(value, "%16[^/]/%i", ip, &prefix) == 2) {
				if(!chipvpn_address_set_ip(&device->address, ip)) {
					return 0;
				}
				device->address.prefix = prefix;
			}
		}

		if(MATCH("interface", "postup")) {
			if(device->flag & CHIPVPN_DEVICE_POSTUP) {
				free(device->postup);
			}
			device->postup = strdup(value);
			device->flag |= CHIPVPN_DEVICE_POSTUP;
		}

		if(MATCH("interface", "postdown")) {
			if(device->flag & CHIPVPN_DEVICE_POSTDOWN) {
				free(device->postdown);
			}
			device->postdown = strdup(value);
			device->flag |= CHIPVPN_DEVICE_POSTDOWN;
		}

		if(MATCH("interface", "name")) {
			if(device->flag & CHIPVPN_DEVICE_NAME) {
				free(device->name);
			}
			device->name = strdup(value);
			device->flag |= CHIPVPN_DEVICE_NAME;
		}

		if(MATCH("interface", "mtu")) {
			device->mtu = atoi(value);
			if(!(device->mtu > 200 && device->mtu < 50000)) {
				return 0;
			}
		}

		chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_back(&device->peers);

		if(MATCH("peer", "key")) {
			chipvpn_peer_set_key(peer, (char*)value);
		}

		if(MATCH("peer", "allow")) {
			chipvpn_peer_set_allow(peer, value);
		}

		if(MATCH("peer", "endpoint")) {
			chipvpn_peer_set_endpoint(peer, value);
		}
	} else {
		if(strcasecmp(section, "peer") == 0) {
			chipvpn_peer_t *peer = chipvpn_peer_create();
			chipvpn_list_insert(chipvpn_list_end(&device->peers), peer);
		}
	}

	return 1;
}

void chipvpn_device_free(chipvpn_device_t *device) {
	while(!chipvpn_list_empty(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&device->peers));
		chipvpn_peer_free(peer);
	}

	if(device->flag & CHIPVPN_DEVICE_POSTUP) {
		free(device->postup);
	}

	if(device->flag & CHIPVPN_DEVICE_POSTDOWN) {
		free(device->postdown);
	}

	if(device->flag & CHIPVPN_DEVICE_NAME) {
		free(device->name);
	}

	free(device);
}