#include "device.h"
#include "peer.h"
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "address.h"
#include "util.h"
#include "base64.h"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

chipvpn_device_t *chipvpn_device_create(int fd) {
	chipvpn_device_t *device = malloc(sizeof(chipvpn_device_t));
	if(!device) {
		return NULL;
	}

	if(fd < 0) {
		fd = open("/dev/net/tun", O_RDWR);
		if(fd < 0) {
			return NULL;
		}

		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

		if(ioctl(fd, TUNSETIFF, &ifr) < 0) {
			close(fd);
			return NULL;
		}

		strcpy(device->dev, ifr.ifr_name);
	}

	chipvpn_socket_t *sock = chipvpn_socket_create(fd);
	if(!sock) {
		return NULL;
	}

	device->fd       = fd;
	device->socket   = sock;
	device->postup   = NULL;
	device->postdown = NULL;

	chipvpn_list_clear(&device->peers);

	return device;
}

uint32_t chipvpn_device_generate_index(chipvpn_device_t *device) {
	uint32_t index;

	chipvpn_secure_random((uint8_t*)&index, sizeof(index));
	if(index == 0) {
		return 0;
	}

	if(chipvpn_device_lookup_peer_by_handshake(device, index) != NULL) {
		return 0;
	}

	if(chipvpn_device_lookup_peer_by_session(device, NULL, index) != NULL) {
		return 0;
	}

	return index;
}

chipvpn_peer_t *chipvpn_device_lookup_peer_by_pubkey(chipvpn_device_t *device, const uint8_t *public) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_secure_memcmp(public, peer->config.public, sizeof(peer->config.public)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_device_lookup_peer_by_ip(chipvpn_device_t *device, chipvpn_address_t *ip) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_address_cidr_match(ip, &peer->config.allow)) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_device_lookup_peer_by_handshake(chipvpn_device_t *device, uint32_t session_id) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(session_id == peer->handshake.inbound_id) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_device_lookup_peer_by_session(chipvpn_device_t *device, chipvpn_peer_session_t **session, uint32_t session_id) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(session_id == peer->prev_session.inbound.id) {
			if(session) {
				*session = &peer->prev_session;
			}
			return peer;
		}

		if(session_id == peer->session.inbound.id) {
			if(session) {
				*session = &peer->session;
			}
			return peer;
		}

		if(session_id == peer->next_session.inbound.id) {
			if(session) {
				*session = &peer->next_session;
			}
			return peer;
		}
	}
	return NULL;
}

bool chipvpn_device_set_postup(chipvpn_device_t *device, const char *command) {
	device->postup = chipvpn_strdup(command);
	return true;
}

bool chipvpn_device_set_postdown(chipvpn_device_t *device, const char *command) {
	device->postdown = chipvpn_strdup(command);
	return true;
}

bool chipvpn_device_set_name(chipvpn_device_t *device, const char *name) {
	struct ifreq ifr;

	strcpy(ifr.ifr_name, device->dev);
	strcpy(ifr.ifr_newname, name);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
        return false;
    }

    int ret = ioctl(fd, SIOCSIFNAME, &ifr) != -1;

	if(ret) {
		strcpy(device->dev, name);
	}

	close(fd);

	return ret;
}

bool chipvpn_device_set_address(chipvpn_device_t *device, chipvpn_address_t *network) {
	bool success = true;

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, device->dev);

	struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
        return false;
    }

	addr->sin_addr.s_addr = network->ip;

	if(ioctl(fd, SIOCSIFADDR, &ifr) == -1) {
		success = false;
	}

	if(network->prefix == 0) {
		addr->sin_addr.s_addr = 0;
	} else {
		addr->sin_addr.s_addr = htonl((0xFFFFFFFFUL << (32 - network->prefix)) & 0xFFFFFFFFUL);
	}

	if(ioctl(fd, SIOCSIFNETMASK, &ifr) == -1) {
		success = false;
	}

	close(fd);

	return success;
}

bool chipvpn_device_set_mtu(chipvpn_device_t *device, int mtu) {
	bool success = true;

	struct ifreq ifr;
	ifr.ifr_addr.sa_family = AF_INET;

	strcpy(ifr.ifr_name, device->dev);

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
        return false;
    }

	ifr.ifr_mtu = mtu;

	if(ioctl(fd, SIOCSIFMTU, &ifr) == -1) {
		success = false;
	}

	close(fd);

	return success;
}

bool chipvpn_device_toggle(chipvpn_device_t *device, bool enable) {
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, device->dev, IFNAMSIZ - 1);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        return false;
    }

    if(ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        close(fd);
        return false;
    }

    if(enable) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }

    bool success = (ioctl(fd, SIOCSIFFLAGS, &ifr) == 0);
    close(fd);

    return success;
}

bool chipvpn_device_set_enabled(chipvpn_device_t *device) {
	if(!chipvpn_device_toggle(device, true)) {
        return false;
    }

	if(device->postup) {
		chipvpn_run_command(device->postup);
	}

	return true;
}

bool chipvpn_device_set_disabled(chipvpn_device_t *device) {
	if(device->postdown) {
		chipvpn_run_command(device->postdown);
	}

	if(!chipvpn_device_toggle(device, false)) {
        return false;
    }

	return true;
}

bool chipvpn_device_set_public_key(chipvpn_device_t *device, const char *key) {
	return b64_decode((uint8_t*)key, strlen(key), device->public) == CURVE25519_KEY_SIZE;
}

bool chipvpn_device_set_private_key(chipvpn_device_t *device, const char *key) {
	if(b64_decode((uint8_t*)key, strlen(key), device->private) != CURVE25519_KEY_SIZE) {
		return false;
	}

	device->private[0] &= 248;
	device->private[31] = (device->private[31] & 127) | 64;

	uint8_t basepoint[CURVE25519_KEY_SIZE] = {9};
	return curve25519(device->public, device->private, basepoint);
}

void chipvpn_device_free(chipvpn_device_t *device) {
	while(!chipvpn_list_empty(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&device->peers));
		chipvpn_peer_free(peer);
	}

	chipvpn_socket_free(device->socket);

	chipvpn_device_set_disabled(device);

	close(device->fd);

	if(device->postup) {
		free(device->postup);
	}

	if(device->postdown) {
		free(device->postdown);
	}

	free(device);
}