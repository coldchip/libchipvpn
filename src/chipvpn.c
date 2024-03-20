#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <sodium.h>
#include "crypto.h"
#include "chipvpn.h"
#include "socket.h"
#include "packet.h"
#include "address.h"
#include "peer.h"
#include "firewall.h"
#include "util.h"

chipvpn_t *chipvpn_create(chipvpn_config_t *config) {
	chipvpn_t *vpn = malloc(sizeof(chipvpn_t));

	setbuf(stdout, 0);
	if(sodium_init() == -1) {
		return NULL;
	}

	/* create vpn device */
	chipvpn_device_t *device = chipvpn_device_create();
	if(!device) {
		return NULL;
	}

	/* create vpn socket */
	chipvpn_socket_t *socket = chipvpn_socket_create();
	if(!socket) {
		return NULL;
	}

	if(!chipvpn_device_set_name(device, config->name)) {
		return NULL;
	}

	if(!chipvpn_device_set_address(device, &config->network)) {
		return NULL;
	}

	if(!chipvpn_device_set_mtu(device, config->mtu)) {
		return NULL;
	}
	
	if(!chipvpn_device_set_enabled(device)) {
		return NULL;
	}

	chipvpn_socket_set_key(socket, config->xor, strlen(config->xor));

	if(config->is_bind) {
		printf("device has bind set\n");
		if(config->is_bind && !chipvpn_socket_bind(socket, &config->bind)) {
			return NULL;
		}
	}

	vpn->device = device;
	vpn->socket = socket;

	vpn->counter = 0;

	return vpn;
}

void chipvpn_wait(chipvpn_t *vpn, uint64_t timeout) {
	fd_set rdset, wdset;
	FD_ZERO(&rdset);
	FD_ZERO(&wdset);

	struct timeval tv;
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

	int max = 0;

	chipvpn_fdset(vpn, &rdset, &wdset, &max);

	if(select(max + 1, &rdset, &wdset, NULL, &tv) >= 0) {
		chipvpn_isset(vpn, &rdset, &wdset);
	}
}

void chipvpn_fdset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset, int *max) {
	int device_max = 0, socket_max = 0;

	chipvpn_device_preselect(vpn->device, rdset, wdset, &device_max);
	chipvpn_socket_preselect(vpn->socket, rdset, wdset, &socket_max);

	*max = MAX(device_max, socket_max);
}

void chipvpn_isset(chipvpn_t *vpn, fd_set *rdset, fd_set *wdset) {
	chipvpn_device_postselect(vpn->device, rdset, wdset);
	chipvpn_socket_postselect(vpn->socket, rdset, wdset);
}

int chipvpn_service(chipvpn_t *vpn) {
	/* peer lifecycle service */
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&vpn->device->peers); p != chipvpn_list_end(&vpn->device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;

		if(chipvpn_get_time() - peer->last_check > 5000) {
			peer->last_check = chipvpn_get_time();

			/* disconnect unpinged peer and check against connect/disconnect timeout timers */
			if(peer->state != PEER_DISCONNECTED && chipvpn_get_time() > peer->timeout) {
				printf("%p says: peer disconnected\n", peer);
				chipvpn_peer_set_status(peer, PEER_DISCONNECTED);
			}

			/* attempt to connect to peer */
			if(peer->state == PEER_DISCONNECTED && peer->connect == true) {
				printf("%p says: connecting\n", peer);
				chipvpn_peer_connect(vpn->socket, peer, true);
			}

			/* ping peers */
			if(peer->state == PEER_CONNECTED) {
				chipvpn_peer_ping(vpn->socket, peer);
			}
		}
	}

	/* tunnel => socket */
	if(chipvpn_device_can_read(vpn->device) && chipvpn_socket_can_write(vpn->socket)) {
		char buffer[vpn->device->mtu];
		int r = chipvpn_device_read(vpn->device, buffer, sizeof(buffer));
		if(r <= 0) {
			return 0;
		}

		ip_hdr_t *ip_hdr = (ip_hdr_t*)buffer;

		chipvpn_address_t dst = {
			.ip = ip_hdr->dst_addr
		};

		chipvpn_peer_t *peer = chipvpn_peer_get_by_allowip(&vpn->device->peers, &dst);
		if(!peer || peer->state != PEER_CONNECTED) {
			return 0;
		}

		if(!chipvpn_firewall_validate_outbound(peer->firewall, buffer)) {
			return 0;
		}

		char packet[sizeof(chipvpn_packet_data_t) + r];

		chipvpn_packet_data_t data = {};
		data.header.type = CHIPVPN_PACKET_DATA;
		data.session = htonl(peer->outbound_session);
		data.counter = htonll(vpn->counter);

		chipvpn_crypto_xchacha20(&peer->outbound_crypto, buffer, r, vpn->counter);
		memcpy(packet, &data, sizeof(data));
		memcpy(packet + sizeof(data), buffer, r);

		vpn->counter++;

		peer->tx += r;

		chipvpn_socket_write(vpn->socket, packet, sizeof(chipvpn_packet_data_t) + r, &peer->address);
	}

	/* socket => tunnel */
	if(chipvpn_socket_can_read(vpn->socket) && chipvpn_device_can_write(vpn->device)) {
		char buffer[sizeof(chipvpn_packet_t) + vpn->device->mtu];
		chipvpn_address_t addr;

		int r = chipvpn_socket_read(vpn->socket, buffer, sizeof(buffer), &addr);
		if(r <= sizeof(chipvpn_packet_header_t)) {
			return 0;
		}

		chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
		switch(header->type) {
			case CHIPVPN_PACKET_AUTH: {
				if(r < sizeof(chipvpn_packet_auth_t)) {
					return 0;
				}

				chipvpn_packet_auth_t *packet = (chipvpn_packet_auth_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(&vpn->device->peers, packet->keyhash);
				if(!peer) {
					return 0;
				}

				if(chipvpn_peer_get_by_session(&vpn->device->peers, ntohl(packet->session))) {
					return 0;
				}

				if(ntohll(packet->timestamp) <= peer->timestamp) {
					return 0;
				}

				if(
					chipvpn_get_time() - 60000 > ntohll(packet->timestamp) ||
					chipvpn_get_time() + 60000 < ntohll(packet->timestamp)
				) {
					return 0;
				}

				char sign[crypto_hash_sha256_BYTES];
				memcpy(sign, packet->sign, sizeof(sign));
				memset(packet->sign, 0, sizeof(packet->sign));

				unsigned char computed_sign[crypto_hash_sha256_BYTES];
				crypto_hash_sha256_state state;
				crypto_hash_sha256_init(&state);
				crypto_hash_sha256_update(&state, (unsigned char*)packet, sizeof(chipvpn_packet_auth_t));
				crypto_hash_sha256_update(&state, (unsigned char*)peer->key, sizeof(peer->key));
				crypto_hash_sha256_final(&state, computed_sign);

				if(memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
					return 0;
				}

				chipvpn_peer_set_status(peer, PEER_DISCONNECTED);

				peer->outbound_session = ntohl(packet->session);
				peer->address = addr;
				peer->timestamp = ntohll(packet->timestamp);
				peer->tx = 0;
				peer->rx = 0;
				peer->timeout = chipvpn_get_time() + 10000;

				chipvpn_peer_set_status(peer, PEER_CONNECTED);

				crypto_stream_xchacha20_xor_ic(
					(unsigned char*)&peer->outbound_crypto, 
					(unsigned char*)&packet->crypto, 
					sizeof(packet->crypto), 
					(unsigned char*)packet->nonce, 
					1024, 
					(unsigned char*)peer->key
				);

				printf("%p says: time difference %lims\n", peer, chipvpn_get_time() - ntohll(packet->timestamp));

				printf("%p says: session id: %u\n", peer, ntohl(packet->session));

				char keyhash_hex[crypto_hash_sha256_BYTES * 2 + 1] = {0};
				sodium_bin2hex(keyhash_hex, sizeof(keyhash_hex), (unsigned char*)&packet->keyhash, sizeof(packet->keyhash));
				printf("%p says: keyhash: %s\n", peer, keyhash_hex);

				char sign_hex[crypto_hash_sha256_BYTES * 2 + 1] = {0};
				sodium_bin2hex(sign_hex, sizeof(sign_hex), (unsigned char*)&sign, sizeof(sign));
				printf("%p says: sign: %s\n", peer, sign_hex);

				struct in_addr ip_addr;
				ip_addr.s_addr = addr.ip;
				printf("%p says: peer connected from [%s:%i]\n", peer, inet_ntoa(ip_addr), addr.port);

				if(packet->ack) {
					printf("%p says: peer requested auth acknowledgement\n", peer);
					chipvpn_peer_connect(vpn->socket, peer, 0);
				}
			}
			break;
			case CHIPVPN_PACKET_DATA: {
				if(r < sizeof(chipvpn_packet_data_t)) {
					return 0;
				}

				chipvpn_packet_data_t *packet = (chipvpn_packet_data_t*)buffer;
				char                  *data   = buffer + sizeof(chipvpn_packet_data_t);

				chipvpn_peer_t *peer = chipvpn_peer_get_by_session(&vpn->device->peers, ntohl(packet->session));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}

				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					return 0;
				}

				chipvpn_crypto_xchacha20(&peer->inbound_crypto, data, r - sizeof(chipvpn_packet_data_t), ntohll(packet->counter));

				ip_hdr_t *ip_hdr = (ip_hdr_t*)data;

				chipvpn_address_t src = {
					.ip = ip_hdr->src_addr
				};

				if(chipvpn_peer_get_by_allowip(&vpn->device->peers, &src) != peer) {
					return 0;
				}

				if(!chipvpn_firewall_validate_inbound(peer->firewall, data)) {
					return 0;
				}

				peer->rx += r - sizeof(chipvpn_packet_data_t);
				chipvpn_device_write(vpn->device, data, r - sizeof(chipvpn_packet_data_t));
			}
			break;
			case CHIPVPN_PACKET_PING: {
				if(r < sizeof(chipvpn_packet_ping_t)) {
					return 0;
				}

				chipvpn_packet_ping_t *packet = (chipvpn_packet_ping_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_session(&vpn->device->peers, ntohl(packet->session));
				if(!peer || peer->state != PEER_CONNECTED) {
					return 0;
				}
				
				if(peer->address.ip != addr.ip || peer->address.port != addr.port) {
					return 0;
				}

				char sign[crypto_hash_sha256_BYTES];
				memcpy(sign, packet->sign, sizeof(sign));
				memset(packet->sign, 0, sizeof(packet->sign));

				unsigned char computed_sign[crypto_hash_sha256_BYTES];
				crypto_hash_sha256_state state;
				crypto_hash_sha256_init(&state);
				crypto_hash_sha256_update(&state, (unsigned char*)packet, sizeof(chipvpn_packet_ping_t));
				crypto_hash_sha256_update(&state, (unsigned char*)peer->key, sizeof(peer->key));
				crypto_hash_sha256_final(&state, computed_sign);

				if(memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
					return 0;
				}

				printf("%p says: received ping from peer\n", peer);

				char tx[128];
				char rx[128];
				strcpy(tx, chipvpn_format_bytes(peer->tx));
				strcpy(rx, chipvpn_format_bytes(peer->rx));

				printf("%p says: tx: [%s] rx: [%s]\n", peer, tx, rx);

				peer->timeout = chipvpn_get_time() + 10000;
			}
			break;
		}
		return 0;
	}
	return 0;
}

void chipvpn_cleanup(chipvpn_t *vpn) {
	for(chipvpn_list_node_t *p = chipvpn_list_begin(&vpn->device->peers); p != chipvpn_list_end(&vpn->device->peers); p = chipvpn_list_next(p)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)p;
		chipvpn_peer_set_status(peer, PEER_DISCONNECTED);
	}

	chipvpn_device_free(vpn->device);
	chipvpn_socket_free(vpn->socket);
}