#include "device.h"
#include "peer.h"
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "address.h"
#include "util.h"
#include "base64.h"
#include "peer.h"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/ipv6.h>

bool chipvpn_device_init(chipvpn_device_t *device) {
	int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if(fd < 0) {
		return false;
	}

	struct ifreq ifr = {0};
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if(ioctl(fd, TUNSETIFF, &ifr) < 0) {
		close(fd);
		return false;
	}

	strncpy(device->dev, ifr.ifr_name, IFNAMSIZ);

	device->fd       = fd;
	device->postup   = NULL;
	device->postdown = NULL;
	chipvpn_list_clear(&device->peers);

	if(!chipvpn_queue_init(&device->tx_queue, 4)) {
		close(fd);
		return false;
	}

	if(!chipvpn_queue_init(&device->rx_queue, 4)) {
		chipvpn_queue_cleanup(&device->tx_queue);
		close(fd);
		return false;
	}

	return true;
}

uint32_t chipvpn_device_generate_index(const chipvpn_device_t *device) {
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

chipvpn_peer_t *chipvpn_device_lookup_peer_by_pubkey(const chipvpn_device_t *device, const uint8_t *public) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_secure_memcmp(public, peer->config.public, sizeof(peer->config.public)) == 0) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_device_lookup_peer_by_ip(const chipvpn_device_t *device, const chipvpn_address_t *address) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_peer_allowip_match(peer, address)) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_device_lookup_peer_by_handshake(const chipvpn_device_t *device, uint32_t session_id) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers); p != chipvpn_list_end(&device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(session_id == peer->handshake.inbound_id) {
			return peer;
		}
	}
	return NULL;
}

chipvpn_peer_t *chipvpn_device_lookup_peer_by_session(const chipvpn_device_t *device, chipvpn_peer_session_t **session, uint32_t session_id) {
	if(session_id == 0) {
		return NULL;
	}

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

void chipvpn_device_peer_service(chipvpn_device_t *device, chipvpn_udp_t *udp) {
	uint64_t now = chipvpn_get_time();

	static uint64_t last_service = 0ULL;

	if(now > last_service + 500) {
		last_service = now;

		chipvpn_list_node_t *p = chipvpn_list_begin(&device->peers);

		while(p != chipvpn_list_end(&device->peers)) {
			chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

			p = chipvpn_list_next(p);

			if(!chipvpn_peer_service(peer, device, udp, now)) {
				chipvpn_list_remove(&peer->node);
				chipvpn_peer_free(peer);
				continue;
			}
		}
	}
}

bool chipvpn_device_set_postup(chipvpn_device_t *device, const char *command) {
	if(device->postup) free(device->postup);
	device->postup = chipvpn_strdup(command);
	return true;
}

bool chipvpn_device_set_postdown(chipvpn_device_t *device, const char *command) {
	if(device->postdown) free(device->postdown);
	device->postdown = chipvpn_strdup(command);
	return true;
}

bool chipvpn_device_set_name(chipvpn_device_t *device, const char *name) {
	struct ifreq ifr = {0};

	strncpy(ifr.ifr_name, device->dev, IFNAMSIZ);
	strncpy(ifr.ifr_newname, name, IFNAMSIZ);

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if(fd < 0) {
		return false;
	}

	int result = ioctl(fd, SIOCSIFNAME, &ifr);

	close(fd);

	if(result < 0) {
		return false;
	}

	strncpy(device->dev, name, IFNAMSIZ);
	return true;
}

bool chipvpn_device_set_address(chipvpn_device_t *device, const chipvpn_address_t *network) {
	int domain;

	switch(network->type) {
		case CHIPVPN_ADDRESS_IPV4: {
			if(network->prefix > 32) {
				return false;
			}
			domain = AF_INET;
		}
		break;
		case CHIPVPN_ADDRESS_IPV6: {
			if(network->prefix > 128) {
				return false;
			}
			domain = AF_INET6;
		}
		break;
		default:
			return false;
	}

	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, device->dev, IFNAMSIZ);

	int fd = socket(domain, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if(fd < 0) {
		return false;
	}

	bool success = false;

	if(network->type == CHIPVPN_ADDRESS_IPV4) {
		struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = network->ipv4;

		if(ioctl(fd, SIOCSIFADDR, &ifr) == 0) {
			uint32_t mask = network->prefix == 0 ? 0 : UINT32_MAX << (32U - network->prefix);

			addr->sin_addr.s_addr = htonl(mask);
			success = ioctl(fd, SIOCSIFNETMASK, &ifr) == 0;
		}
	} else {
		if(ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
			struct in6_ifreq ifr6 = {0};
			ifr6.ifr6_prefixlen = network->prefix;
			ifr6.ifr6_ifindex   = ifr.ifr_ifindex;
			memcpy(&ifr6.ifr6_addr, network->ipv6, sizeof(ifr6.ifr6_addr));

			success = ioctl(fd, SIOCSIFADDR, &ifr6) == 0;
		}
	}

	close(fd);
	return success;
}

bool chipvpn_device_set_mtu(chipvpn_device_t *device, int mtu) {
	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, device->dev, IFNAMSIZ);
	ifr.ifr_mtu = mtu;

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if(fd < 0) {
		return false;
	}

	bool success = ioctl(fd, SIOCSIFMTU, &ifr) == 0;
	close(fd);

	return success;
}


bool chipvpn_device_set_txqueuelen(chipvpn_device_t *device, int qlen) {
	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, device->dev, IFNAMSIZ);
	ifr.ifr_qlen = qlen;

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if(fd < 0) {
		return false;
	}

	bool success = ioctl(fd, SIOCSIFTXQLEN, &ifr) == 0;
	close(fd);

	return success;
}

bool chipvpn_device_toggle(chipvpn_device_t *device, bool enable) {
	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, device->dev, IFNAMSIZ);

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if(fd < 0) {
		return false;
	}

	if(ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return false;
	}

	bool is_enabled = (ifr.ifr_flags & IFF_UP) != 0;
	if(is_enabled == enable) {
		close(fd);
		return true;
	}

	if(enable) {
		ifr.ifr_flags |= IFF_UP;
	} else {
		ifr.ifr_flags &= (short)~IFF_UP;
	}

	bool success = ioctl(fd, SIOCSIFFLAGS, &ifr) == 0;
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

bool chipvpn_device_set_private_key(chipvpn_device_t *device, const char *key) {
	if(b64_decode((const uint8_t*)key, strlen(key), device->private) != CURVE25519_KEY_SIZE) {
		return false;
	}

	device->private[0] &= 248;
	device->private[31] = (device->private[31] & 127) | 64;

	uint8_t basepoint[CURVE25519_KEY_SIZE] = {9};
	return curve25519(device->public, device->private, basepoint);
}

void chipvpn_device_preselect(chipvpn_device_t *device, fd_set *rdset, fd_set *wdset, int *max) {
	if(chipvpn_queue_push_acquire(&device->rx_queue)) FD_SET(device->fd, rdset); else FD_CLR(device->fd, rdset);
	if(chipvpn_queue_pop_acquire(&device->tx_queue))  FD_SET(device->fd, wdset); else FD_CLR(device->fd, wdset);
	*max = device->fd;
}

void chipvpn_device_postselect(chipvpn_device_t *device, fd_set *rdset, fd_set *wdset) {
	if(FD_ISSET(device->fd, rdset)) {
		chipvpn_queue_entry_t *entry = chipvpn_queue_push_acquire(&device->rx_queue);
		if(entry) {
			ssize_t r = read(device->fd, entry->buffer, sizeof(entry->buffer));
			if(r > 0) {
				entry->size = (uint16_t)r;
				chipvpn_queue_push_commit(&device->rx_queue, entry);
			}
		}
	}
	if(FD_ISSET(device->fd, wdset)) {
		chipvpn_queue_entry_t *entry = chipvpn_queue_pop_acquire(&device->tx_queue);
		if(entry) {
			ssize_t w = write(device->fd, entry->buffer, entry->size);
			if(w > 0) {
				entry->size = (uint16_t)0u;
				chipvpn_queue_pop_commit(&device->tx_queue, entry);
			}
		}
	}
}

void chipvpn_device_cleanup(chipvpn_device_t *device) {
	while(!chipvpn_list_empty(&device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&device->peers));
		chipvpn_peer_free(peer);
	}

	chipvpn_device_set_disabled(device);

	chipvpn_queue_cleanup(&device->tx_queue);
	chipvpn_queue_cleanup(&device->rx_queue);

	close(device->fd);

	if(device->postup) {
		free(device->postup);
	}

	if(device->postdown) {
		free(device->postdown);
	}
}