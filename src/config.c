#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <stdlib.h>
#include "log.h"
#include "peer.h"
#include "firewall.h"
#include "device.h"
#include "config.h"
#include "base64.h"
#include "util.h"

int section = 0;

void chipvpn_config_command(chipvpn_t *vpn, const char *command) {
	char line[8192];
	while(chipvpn_sgets(line, sizeof(line), (const char **)&command)) {
		line[strcspn(line, "\r\n")] = 0;
		if(line[0] == '\0') {
			continue;
		}

		char key[128];
		char value[4096];
		if(sscanf(line, "%24[^:]:%1024[^\n]", key, value) != 2) {
			LOG_FATAL("failed to parse config entry [%s]", line);
			return;
		}

		if(strcmp(key, "section") == 0) {
			if(strcmp(value, "device") == 0) {
				section = COMMAND_DEVICE_SECTION;
				continue;
			}

			if(strcmp(value, "peer") == 0) {
				section = COMMAND_PEER_SECTION;

				chipvpn_peer_t *peer = chipvpn_peer_create();
				if(!peer) {
					LOG_FATAL("failed to allocate peer");
					return;
				}

				chipvpn_list_insert(chipvpn_list_end(&vpn->device.peers), peer);
				peer->last_created = chipvpn_get_tick();
				continue;
			}

			LOG_WARN("unknown section [%s], ignoring", value);
			continue;
		}

		if(strcmp(key, "remove") == 0) {
			char key_b64[1024];
			if(sscanf(value, "%1023s", key_b64) != 1) {
				LOG_FATAL("failed to parse remove key [%s]", value);
				return;
			}

			uint8_t key32[CURVE25519_KEY_SIZE];
			if(b64_decode((const uint8_t*)key_b64, strlen(key_b64), key32) != CURVE25519_KEY_SIZE) {
				LOG_FATAL("invalid base64 public key for remove [%s]", key_b64);
				return;
			}

			chipvpn_peer_t *peer = chipvpn_device_lookup_peer_by_pubkey(&vpn->device, key32);
			if(!peer) {
				LOG_FATAL("peer not found for remove [%s]", key_b64);
				return;
			}

			chipvpn_list_remove(&peer->node);
			chipvpn_peer_free(peer);
			continue;
		}

		if(section == COMMAND_DEVICE_SECTION) {
			if(strcmp(key, "cpu") == 0) {
				int cpu;
				if(sscanf(value, "%i", &cpu) != 1 || cpu < 0 || cpu >= CPU_SETSIZE) {
					LOG_FATAL("failed to parse cpu [%s]", value);
					return;
				}

				cpu_set_t set;
				CPU_ZERO(&set);
				CPU_SET(cpu, &set);

				if(sched_setaffinity(0, sizeof(cpu_set_t), &set) != 0) {
					LOG_FATAL("failed to set cpu affinity [%i]", cpu);
					return;
				}
				continue;
			}

			if(strcmp(key, "name") == 0) {
				char name[IF_NAMESIZE + 1];
				if(sscanf(value, "%16[^\n]", name) != 1) {
					LOG_FATAL("failed to parse interface name [%s]", value);
					return;
				}

				if(!chipvpn_device_set_name(&vpn->device, name)) {
					LOG_FATAL("failed to set interface name [%s]", name);
					return;
				}

				LOG_INFO("interface name [%s]", name);
				continue;
			}

			if(strcmp(key, "network") == 0) {
				char address[128];
				int prefix;
				if(sscanf(value, "[%45[^]]]/%i", address, &prefix) != 2 && sscanf(value, "%45[^/]/%i", address, &prefix) != 2) {
					LOG_FATAL("failed to parse network [%s]", value);
					return;
				}

				chipvpn_address_t network;
				if(!chipvpn_address_set_ip(&network, address)) {
					LOG_FATAL("invalid network address [%s]", address);
					return;
				}

				if(
					(network.type == CHIPVPN_ADDRESS_IPV6 && (prefix < 0 || prefix > 128)) ||
					(network.type == CHIPVPN_ADDRESS_IPV4 && (prefix < 0 || prefix > 32))
				) {
					LOG_FATAL("invalid network prefix [%i] for [%s]", prefix, address);
					return;
				}

				network.prefix = (uint8_t)prefix;
				if(!chipvpn_device_set_address(&vpn->device, &network)) {
					LOG_FATAL("failed to set interface address [%s]/%i", address, prefix);
					return;
				}

				LOG_INFO("interface address: [%s]/%u", chipvpn_address_to_char(&network), network.prefix);
				continue;
			}

			if(strcmp(key, "private") == 0) {
				char key_b64[1024];
				if(sscanf(value, "%1023s", key_b64) != 1) {
					LOG_FATAL("failed to parse private key");
					return;
				}

				chipvpn_device_set_private_key(&vpn->device, key_b64);
				continue;
			}

			if(strcmp(key, "mtu") == 0) {
				int mtu;
				if(sscanf(value, "%i", &mtu) != 1 || mtu <= 0) {
					LOG_FATAL("failed to parse mtu [%s]", value);
					return;
				}

				if(!chipvpn_device_set_mtu(&vpn->device, mtu)) {
					LOG_FATAL("failed to set interface mtu [%i]", mtu);
					return;
				}

				LOG_INFO("interface mtu [%u]", (unsigned int)mtu);
				continue;
			}

			if(strcmp(key, "txqueuelen") == 0) {
				int qlen;
				if(sscanf(value, "%i", &qlen) != 1 || qlen < 0) {
					LOG_FATAL("failed to parse txqueuelen [%s]", value);
					return;
				}

				if(!chipvpn_device_set_txqueuelen(&vpn->device, qlen)) {
					LOG_FATAL("failed to set interface txqueuelen [%i]", qlen);
					return;
				}

				LOG_INFO("interface txqueuelen [%u]", (unsigned int)qlen);
				continue;
			}

			if(strcmp(key, "bind") == 0) {
				char address[128];
				int port;
				if(sscanf(value, "[%45[^]]]:%i", address, &port) != 2 && sscanf(value, "%45[^:]:%i", address, &port) != 2) {
					LOG_FATAL("failed to parse bind [%s]", value);
					return;
				}

				if(port < 0 || port > 65535) {
					LOG_FATAL("invalid bind port [%i]", port);
					return;
				}

				chipvpn_address_t bind;
				if(!chipvpn_address_set_ip(&bind, address)) {
					LOG_FATAL("invalid bind address [%s]", address);
					return;
				}

				bind.port = (uint16_t)port;
				if(!chipvpn_udp_bind(&vpn->udp, &bind)) {
					LOG_FATAL("failed to bind to [%s]:%u", address, bind.port);
					return;
				}

				LOG_INFO("binding to [%s]:%u", chipvpn_address_to_char(&bind), bind.port);
				continue;
			}

			if(strcmp(key, "sendbuf") == 0) {
				int sendbuf;
				if(sscanf(value, "%i", &sendbuf) != 1 || sendbuf <= 0) {
					LOG_FATAL("failed to parse sendbuf [%s]", value);
					return;
				}

				chipvpn_udp_set_sendbuf(&vpn->udp, sendbuf);
				LOG_INFO("interface sendbuf [%u] byte(s)", (unsigned int)sendbuf);
				continue;
			}

			if(strcmp(key, "recvbuf") == 0) {
				int recvbuf;
				if(sscanf(value, "%i", &recvbuf) != 1 || recvbuf <= 0) {
					LOG_FATAL("failed to parse recvbuf [%s]", value);
					return;
				}

				chipvpn_udp_set_recvbuf(&vpn->udp, recvbuf);
				LOG_INFO("interface recvbuf [%u] byte(s)", (unsigned int)recvbuf);
				continue;
			}

			if(strcmp(key, "fwmark") == 0) {
				int fwmark;
				if(sscanf(value, "%i", &fwmark) != 1) {
					LOG_FATAL("failed to parse fwmark [%s]", value);
					return;
				}

				chipvpn_udp_set_fwmark(&vpn->udp, fwmark);
				LOG_INFO("interface fwmark [%i]", fwmark);
				continue;
			}

			if(strcmp(key, "postup") == 0) {
				chipvpn_device_set_postup(&vpn->device, value);
				continue;
			}

			if(strcmp(key, "postdown") == 0) {
				chipvpn_device_set_postdown(&vpn->device, value);
				continue;
			}

			if(strcmp(key, "ifup") == 0) {
				chipvpn_device_set_enabled(&vpn->device);
				continue;
			}

			if(strcmp(key, "ifdown") == 0) {
				chipvpn_device_set_disabled(&vpn->device);
				continue;
			}

			LOG_WARN("unknown device config key [%s], ignoring", key);
			continue;
		}

		if(section == COMMAND_PEER_SECTION) {
			chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_back(&vpn->device.peers);
			if(!peer) {
				LOG_FATAL("no active peer for config key [%s]", key);
				return;
			}

			if(strcmp(key, "ephemeral") == 0) {
				peer->type = PEER_EPHEMERAL;
				continue;
			}

			if(strcmp(key, "address") == 0) {
				char address[128];
				int port;
				if(sscanf(value, "[%45[^]]]:%i", address, &port) != 2 && sscanf(value, "%45[^:]:%i", address, &port) != 2) {
					LOG_FATAL("failed to parse peer address [%s]", value);
					return;
				}

				if(port < 0 || port > 65535) {
					LOG_FATAL("invalid peer port [%i]", port);
					return;
				}

				if(!chipvpn_peer_set_endpoint(peer, address, (uint16_t)port)) {
					LOG_FATAL("failed to set peer endpoint [%s]:%i", address, port);
					return;
				}
				continue;
			}

			if(strcmp(key, "allow") == 0) {
				char address[128];
				int prefix;
				if(sscanf(value, "[%45[^]]]/%i", address, &prefix) != 2 && sscanf(value, "%45[^/]/%i", address, &prefix) != 2) {
					LOG_FATAL("failed to parse peer allow [%s]", value);
					return;
				}

				if(prefix < 0 || prefix > 128) {
					LOG_FATAL("invalid peer allow prefix [%i] for [%s]", prefix, address);
					return;
				}

				if(!chipvpn_peer_add_allowip(peer, address, (uint8_t)prefix)) {
					LOG_FATAL("failed to add peer allow ip [%s]/%i", address, prefix);
					return;
				}
				continue;
			}

			if(strcmp(key, "public") == 0) {
				char key_b64[1024];
				if(sscanf(value, "%1023s", key_b64) != 1) {
					LOG_FATAL("failed to parse peer public key");
					return;
				}

				if(!chipvpn_peer_set_public_key(peer, &vpn->device, key_b64)) {
					LOG_FATAL("invalid peer public key [%s]", key_b64);
					return;
				}
				continue;
			}

			if(strcmp(key, "psk") == 0) {
				char key_b64[1024];
				if(sscanf(value, "%1023s", key_b64) != 1) {
					LOG_FATAL("failed to parse peer psk");
					return;
				}

				if(!chipvpn_peer_set_psk(peer, key_b64)) {
					LOG_FATAL("invalid peer psk");
					return;
				}
				continue;
			}

			if(strcmp(key, "inbound") == 0) {
				char address[128];
				int prefix;
				if(sscanf(value, "[%45[^]]]/%i", address, &prefix) != 2 && sscanf(value, "%45[^/]/%i", address, &prefix) != 2) {
					LOG_FATAL("failed to parse peer inbound [%s]", value);
					return;
				}

				chipvpn_address_t entry;
				if(!chipvpn_address_set_ip(&entry, address)) {
					LOG_FATAL("invalid peer inbound address [%s]", address);
					return;
				}

				if(
					(entry.type == CHIPVPN_ADDRESS_IPV6 && (prefix < 0 || prefix > 128)) ||
					(entry.type == CHIPVPN_ADDRESS_IPV4 && (prefix < 0 || prefix > 32))
				) {
					LOG_FATAL("invalid peer inbound prefix [%i] for [%s]", prefix, address);
					return;
				}

				entry.prefix = (uint8_t)prefix;
				chipvpn_firewall_insert(&peer->firewall_inbound, &entry);
				continue;
			}

			if(strcmp(key, "outbound") == 0) {
				char address[128];
				int prefix;
				if(sscanf(value, "[%45[^]]]/%i", address, &prefix) != 2 && sscanf(value, "%45[^/]/%i", address, &prefix) != 2) {
					LOG_FATAL("failed to parse peer outbound [%s]", value);
					return;
				}

				chipvpn_address_t entry;
				if(!chipvpn_address_set_ip(&entry, address)) {
					LOG_FATAL("invalid peer outbound address [%s]", address);
					return;
				}

				if(
					(entry.type == CHIPVPN_ADDRESS_IPV6 && (prefix < 0 || prefix > 128)) ||
					(entry.type == CHIPVPN_ADDRESS_IPV4 && (prefix < 0 || prefix > 32))
				) {
					LOG_FATAL("invalid peer outbound prefix [%i] for [%s]", prefix, address);
					return;
				}

				entry.prefix = (uint8_t)prefix;
				chipvpn_firewall_insert(&peer->firewall_outbound, &entry);
				continue;
			}

			LOG_WARN("unknown peer config key [%s], ignoring", key);
			continue;
		}

		LOG_WARN("config key [%s] outside valid section, ignoring", key);
		continue;
	}
}