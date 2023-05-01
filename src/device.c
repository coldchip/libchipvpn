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

	list_clear(&device->peers);
	device->flag = 0;
	device->postup = NULL;
	device->postdown = NULL;
	device->name = NULL;
	device->mtu = 1420;
	device->qlen = 2000;

	if(!chipvpn_device_reload_config(device, file)) {
		return NULL;
	}

	return device;
}

bool chipvpn_device_reload_config(chipvpn_device_t *device, char *file) {
	List temp;
	list_clear(&temp);

	// move every peer from device to temp
	while(!list_empty(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)list_remove(list_begin(&device->peers));
		list_insert(list_end(&temp), peer);
	}

	// clear device peers
	list_clear(&device->peers);

	// reload config
	if(ini_parse(file, chipvpn_device_parse_handler, device) < 0) {
		return false;
	}

	// move connected peers from temp to device
	ListNode *p = list_begin(&device->peers);
	while(p != list_end(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		p = list_next(p);

		ListNode *t = list_begin(&temp);
		while(t != list_end(&temp)) {
			chipvpn_peer_t *peer1 = (chipvpn_peer_t*)t;
			t = list_next(t);

			if(memcmp(peer->crypto->key, peer1->crypto->key, sizeof(peer->crypto->key)) == 0 && peer1->state == PEER_CONNECTED) {
				list_remove(&peer->node);
				chipvpn_peer_free(peer);

				list_remove(&peer1->node);
				list_insert(list_end(&device->peers), peer1);
			}
		}
	}

	// remove deleted peers from temp
	while(!list_empty(&temp)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)list_remove(list_begin(&temp));
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
					chipvpn_error("invalid ip address: %s", ip);
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
					chipvpn_error("invalid ip address: %s", ip);
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
		}

		if(MATCH("interface", "qlen")) {
			device->qlen = atoi(value);
		}

		chipvpn_peer_t *peer = (chipvpn_peer_t*)list_back(&device->peers);

		if(MATCH("peer", "key")) {
			char keyhash[crypto_stream_xchacha20_KEYBYTES];
			crypto_hash_sha256((unsigned char*)keyhash, (unsigned char*)value, strlen(value));
			chipvpn_crypto_set_key(peer->crypto, keyhash);
		}

		if(MATCH("peer", "allow")) {
			char ip[24];
			int prefix;
			if(sscanf(value, "%16[^/]/%i", ip, &prefix) == 2) {
				if(!chipvpn_address_set_ip(&peer->allow, ip)) {
					chipvpn_error("invalid ip address: %s", ip);
				}
				peer->allow.prefix = prefix;
			}
		}

		if(MATCH("peer", "endpoint")) {
			char ip[24];
			int port;
			if(sscanf(value, "%254[^:]:%i", ip, &port) == 2) {
				if(!chipvpn_address_set_domain(&peer->address, ip)) {
					chipvpn_error("unable to resolve %s", ip);
				}
				peer->address.port = port;
				peer->connect = true;
			}
		}
	} else {
		if(strcasecmp(section, "peer") == 0) {
			chipvpn_peer_t *peer = chipvpn_peer_create();
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

	free(device);
}