#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "peer.h"
#include "device.h"
#include "ini.h"

chipvpn_device_t *chipvpn_device_create(char *file) {
	chipvpn_device_t *device = malloc(sizeof(chipvpn_device_t));
	if(!device) {
		return NULL;
	}

	list_clear(&device->peers);
	device->flag = 0;
	device->postup = NULL;
	device->postdown = NULL;
	device->name = NULL;
	device->mtu = 1420;

	if(ini_parse(file, chipvpn_device_parse_handler, device) < 0) {
		return NULL;
	}

	device->tun = chipvpn_tun_create(device->name);
	if(!device->tun) {
		return NULL;
	}

	device->sock = chipvpn_socket_create();
	if(device->sock < 0) {
		return NULL;
	}

	return device;
}

int chipvpn_device_parse_handler(void* user, const char* section, const char* name, const char* value) {
	chipvpn_device_t* device = (chipvpn_device_t*)user;

	#define MATCH(s, n) strcasecmp(section, s) == 0 && strcasecmp(name, n) == 0

	if(name && value) {
		if(MATCH("interface", "bind")) {
			char ip[24];
			int port;
			if(sscanf(value, "%16[^:]:%i", ip, &port) == 2) {
				chipvpn_address_set_ip(&device->bind, ip);
				device->bind.port = port;
				device->flag |= CHIPVPN_DEVICE_BIND;
			}
		}

		if(MATCH("interface", "address")) {
			char ip[24];
			int prefix;
			if(sscanf(value, "%16[^/]/%i", ip, &prefix) == 2) {
				chipvpn_address_set_ip(&device->address, ip);
				device->address.prefix = prefix;
			}
		}

		if(MATCH("interface", "postup")) {
			device->postup = strdup(value);
			device->flag |= CHIPVPN_DEVICE_POSTUP;
		}

		if(MATCH("interface", "postdown")) {
			device->postdown = strdup(value);
			device->flag |= CHIPVPN_DEVICE_POSTDOWN;
		}

		if(MATCH("interface", "name")) {
			device->name = strdup(value);
			device->flag |= CHIPVPN_DEVICE_NAME;
		}

		if(MATCH("interface", "mtu")) {
			device->mtu = atoi(value);
		}

		chipvpn_peer_t *peer = (chipvpn_peer_t*)list_back(&device->peers);

		if(MATCH("peer", "id")) {
			peer->id = atoi(value);
		}

		if(MATCH("peer", "key")) {
			chipvpn_crypto_set_key(peer->crypto, (char*)value);
		}

		if(MATCH("peer", "allow")) {
			char ip[24];
			int prefix;
			if(sscanf(value, "%16[^/]/%i", ip, &prefix) == 2) {
				chipvpn_address_set_ip(&peer->allow, ip);
				peer->allow.prefix = prefix;
			}
		}

		if(MATCH("peer", "endpoint")) {
			char ip[24];
			int port;
			if(sscanf(value, "%16[^:]:%i", ip, &port) == 2) {
				chipvpn_address_set_ip(&peer->address, ip);
				peer->address.port = port;
				peer->connect = true;
			}
		}
	} else {
		if(strcasecmp(section, "peer") == 0) {
			chipvpn_peer_t *peer = chipvpn_peer_create();
			peer->connect = false;
			list_insert(list_end(&device->peers), peer);
		}
	}

	return 1;
}

void chipvpn_device_free(chipvpn_device_t *device) {
	while(!list_empty(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)list_remove(list_begin(&device->peers));
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

	chipvpn_tun_free(device->tun);
	chipvpn_socket_free(device->sock);

	free(device);
}