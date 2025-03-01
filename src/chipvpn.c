#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "crypto.h"
#include "chipvpn.h"
#include "socket.h"
#include "packet.h"
#include "address.h"
#include "peer.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include "xchacha20.h"
#include "util.h"

chipvpn_t *chipvpn_create(chipvpn_config_t *config, int tun_fd) {
	chipvpn_t *vpn = malloc(sizeof(chipvpn_t));

	setbuf(stdout, 0);

	/* create vpn device */
	chipvpn_device_t *device = chipvpn_device_create(tun_fd);
	if(!device) {
		return NULL;
	}

	/* create vpn socket */
	chipvpn_socket_t *socket = chipvpn_socket_create();
	if(!socket) {
		return NULL;
	}

	if(tun_fd < 0) {
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
	}

	if(config->sendbuf > 0 && !chipvpn_socket_set_sendbuf(socket, config->sendbuf)) {
		return NULL;
	}

	if(config->recvbuf > 0 && !chipvpn_socket_set_recvbuf(socket, config->recvbuf)) {
		return NULL;
	}

	if(config->is_bind) {
		printf("device has bind set\n");
		if(!chipvpn_socket_bind(socket, &config->bind)) {
			return NULL;
		}
	}

	vpn->device = device;
	vpn->socket = socket;

	vpn->counter = 0;

	return vpn;
}

void chipvpn_poll(chipvpn_t *vpn, uint64_t timeout) {
	fd_set rdset, wdset;
	FD_ZERO(&rdset);
	FD_ZERO(&wdset);

	struct timeval tv;
	tv.tv_sec = timeout / 1000;
	tv.tv_usec = (timeout % 1000) * 1000;

	int max = 0;

	chipvpn_fdset(vpn, &rdset, &wdset, &max);

	if(select(max + 1, &rdset, &wdset, NULL, &tv) > 0) {
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

	chipvpn_list_node_t *i = chipvpn_list_begin(&vpn->device->peers);
	while(i != chipvpn_list_end(&vpn->device->peers)) {
		chipvpn_peer_t *peer = (chipvpn_peer_t*)i;
		i = chipvpn_list_next(i);

		if(chipvpn_get_time() - peer->last_check > CHIPVPN_PEER_PING) {
			peer->last_check = chipvpn_get_time();

			/* disconnect unpinged peer and check against connect/disconnect timeout timers */
			if(peer->state != PEER_DISCONNECTED && chipvpn_get_time() > peer->timeout) {
				printf("%p says: peer disconnected\n", peer);
				chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
			}

			/* attempt to connect to peer */
			if(peer->state == PEER_DISCONNECTED && peer->connect == true) {
				printf("%p says: connecting to [%s:%i]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);

				chipvpn_peer_connect(vpn->socket, peer, 1);
			}

			/* ping peers */
			if(peer->state == PEER_CONNECTED) {
				chipvpn_peer_ping(vpn->socket, peer);
			}
		}
	}

	/* tunnel => socket */
	if(chipvpn_device_can_read(vpn->device) && chipvpn_socket_can_write(vpn->socket)) {
		char buffer[SOCKET_QUEUE_ENTRY_SIZE];

		chipvpn_packet_data_t *header = (chipvpn_packet_data_t*)buffer;
		char                  *data   = buffer + sizeof(chipvpn_packet_data_t);

		int r = chipvpn_device_read(vpn->device, data, sizeof(buffer) - sizeof(chipvpn_packet_data_t));
		if(r <= 0) {
			return 0;
		}

		ip_hdr_t *ip_hdr = (ip_hdr_t*)data;
		chipvpn_address_t dst = {
			.ip = ip_hdr->dst_addr
		};

		chipvpn_peer_t *peer = chipvpn_peer_get_by_allowip(&vpn->device->peers, &dst);
		if(!peer || peer->state != PEER_CONNECTED) {
			return 0;
		}

		header->header.type = CHIPVPN_PACKET_DATA;
		header->session     = htonl(peer->outbound_session);
		header->counter     = htonll(vpn->counter);

		chipvpn_crypto_xchacha20(&peer->outbound_crypto, data, r, vpn->counter++);

		peer->tx += r;
		chipvpn_socket_write(vpn->socket, buffer, sizeof(chipvpn_packet_data_t) + r, &peer->address);
	}

	/* socket => tunnel */
	if(chipvpn_socket_can_read(vpn->socket) && chipvpn_device_can_write(vpn->device)) {
		char buffer[SOCKET_QUEUE_ENTRY_SIZE];
		chipvpn_address_t addr;

		int r = chipvpn_socket_read(vpn->socket, buffer, sizeof(buffer), &addr);
		if(r < sizeof(chipvpn_packet_header_t)) {
			return 0;
		}

		chipvpn_packet_header_t *header = (chipvpn_packet_header_t*)buffer;
		switch(header->type) {
			case CHIPVPN_PACKET_CHALLENGE: {
				if(r < sizeof(chipvpn_packet_challenge_t)) {
					return 0;
				}

				chipvpn_packet_challenge_t *packet = (chipvpn_packet_challenge_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(&vpn->device->peers, packet->keyhash);
				if(!peer) {
					return 0;
				}

				chipvpn_secure_random(peer->challenge, sizeof(peer->challenge));

				chipvpn_packet_challenge_reply_t reply = {
					.header.type = CHIPVPN_PACKET_CHALLENGE_REPLY,
					.id = packet->id
				};
				memcpy(reply.keyhash, packet->keyhash, sizeof(packet->keyhash));
				memcpy(reply.challenge, peer->challenge, sizeof(peer->challenge));

				chipvpn_socket_write(vpn->socket, &reply, sizeof(reply), &addr);
			}
			break;
			case CHIPVPN_PACKET_CHALLENGE_REPLY: {
				if(r < sizeof(chipvpn_packet_challenge_reply_t)) {
					return 0;
				}
				
				chipvpn_packet_challenge_reply_t *packet = (chipvpn_packet_challenge_reply_t*)buffer;

				chipvpn_peer_t *peer = chipvpn_peer_get_by_keyhash(&vpn->device->peers, packet->keyhash);
				if(!peer) {
					return 0;
				}

				chipvpn_list_node_t *r = chipvpn_list_begin(&peer->challenges);
				while(r != chipvpn_list_end(&peer->challenges)) {
					chipvpn_peer_challenge_receipt_t *receipt = (chipvpn_peer_challenge_receipt_t*)r;
					r = chipvpn_list_next(r);

					if(ntohll(packet->id) == receipt->id) {
						chipvpn_peer_connect_challenge(vpn->socket, peer, packet->challenge, receipt->ack);
						chipvpn_list_remove(&receipt->node);
						free(receipt);
					}
				}
			}
			break;
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
					printf("session collision\n");
					return 0;
				}

				if(ntohl(packet->version) != CHIPVPN_PROTOCOL_VERSION) {
					printf("invalid protocol version\n");
					return 0;
				}

				if(memcmp(packet->challenge, peer->challenge, sizeof(peer->challenge)) != 0) {
					printf("packet has invalid challenge code\n");
					return 0;
				}

				char sign[32];
				char computed_sign[32];
				memcpy(sign, packet->sign, sizeof(sign));
				memset(packet->sign, 0, sizeof(packet->sign));

				hmac_sha256(
					peer->key, 
					sizeof(peer->key),
					packet,
					sizeof(chipvpn_packet_auth_t),
					computed_sign,
					sizeof(computed_sign)
				);

				if(memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
					printf("invalid sign\n");
					return 0;
				}

				chipvpn_peer_set_state(peer, PEER_DISCONNECTED);

				peer->outbound_session = ntohl(packet->session);
				peer->address = addr;
				peer->tx = 0l;
				peer->rx = 0l;
				peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;

				chipvpn_peer_set_state(peer, PEER_CONNECTED);

				hmac_sha256(
					peer->key, 
					sizeof(peer->key),
					packet->nonce,
					sizeof(packet->nonce),
					peer->outbound_crypto.key,
					sizeof(peer->outbound_crypto.key)
				);
				memcpy(peer->outbound_crypto.nonce, packet->nonce, sizeof(packet->nonce));

				if(packet->ack) {
					printf("%p says: peer requested auth acknowledgement\n", peer);
					chipvpn_peer_connect(vpn->socket, peer, 0);
				}

				printf("%p says: hello\n", peer);
				printf("%p says: peer connected from [%s:%i]\n", peer, chipvpn_address_to_char(&peer->address), peer->address.port);
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

				char sign[32];
				char computed_sign[32];
				memcpy(sign, packet->sign, sizeof(sign));
				memset(packet->sign, 0, sizeof(packet->sign));

				hmac_sha256(
					peer->key, 
					sizeof(peer->key),
					packet,
					sizeof(chipvpn_packet_ping_t),
					computed_sign,
					sizeof(computed_sign)
				);

				if(memcmp(sign, computed_sign, sizeof(computed_sign)) != 0) {
					return 0;
				}

				printf("%p says: received ping from peer\n", peer);

				char tx[128];
				char rx[128];
				strcpy(tx, chipvpn_format_bytes(peer->tx));
				strcpy(rx, chipvpn_format_bytes(peer->rx));

				printf("%p says: tx: [%s] rx: [%s]\n", peer, tx, rx);

				peer->timeout = chipvpn_get_time() + CHIPVPN_PEER_TIMEOUT;
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
		chipvpn_peer_set_state(peer, PEER_DISCONNECTED);
	}

	chipvpn_device_free(vpn->device);
	chipvpn_socket_free(vpn->socket);
}