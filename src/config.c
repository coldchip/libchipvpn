#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <stdlib.h>
#include "peer.h"
#include "device.h"
#include "config.h"
#include "util.h"

/*
 * Parse a batch of newline-separated "key:value" configuration commands and
 * apply them to the running VPN instance.
 *
 * The parser is stateful across lines within a single call: a "section:device"
 * or "section:peer" line switches the active section for the lines that follow.
 * Keeping the section as a local (rather than a file-scope global) makes the
 * parser re-entrant and prevents state from leaking between invocations.
 */
void chipvpn_config_command(chipvpn_t *vpn, const char *command) {
	chipvpn_command_section_e section = COMMAND_DEVICE_SECTION;

	char line[8192];
	while(chipvpn_sgets(line, sizeof(line), &command)) {
		line[strcspn(line, "\n")] = 0;

		char key[128];
		char value[4096];
		if(sscanf(line, "%24[^:]:%1024[^\n]", key, value) != 2) {
			continue;
		}

		/* section switches */
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

		/* section-independent commands */
		if(strcmp(key, "clear") == 0) {
			while(!chipvpn_list_empty(&vpn->device->peers)) {
				chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_remove(chipvpn_list_begin(&vpn->device->peers));
				chipvpn_peer_free(peer);
			}
			continue;
		}

		/* device section */
		if(section == COMMAND_DEVICE_SECTION) {
			if(strcmp(key, "cpu") == 0) {
				int cpu;
				if(sscanf(value, "%i", &cpu) == 1) {
					cpu_set_t set;
					CPU_SET(cpu, &set);
					if(sched_setaffinity(0, sizeof(cpu_set_t), &set) != 0) {
						return;
					}
				}
			} else if(strcmp(key, "name") == 0) {
				char name[IF_NAMESIZE + 1];
				if(sscanf(value, "%16[^\n]", name) == 1) {
					if(!chipvpn_device_set_name(vpn->device, name)) {
						return;
					}
				}
			} else if(strcmp(key, "network") == 0) {
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
			} else if(strcmp(key, "public") == 0) {
				char pubkey[1024];
				if(sscanf(value, "%1023s", pubkey) == 1) {
					chipvpn_device_set_public_key(vpn->device, pubkey);
				}
			} else if(strcmp(key, "private") == 0) {
				char privkey[1024];
				if(sscanf(value, "%1023s", privkey) == 1) {
					chipvpn_device_set_private_key(vpn->device, privkey);
				}
			} else if(strcmp(key, "mtu") == 0) {
				int mtu;
				if(sscanf(value, "%i", &mtu) == 1) {
					if(!chipvpn_device_set_mtu(vpn->device, mtu)) {
						return;
					}
				}
			} else if(strcmp(key, "bind") == 0) {
				char address[24];
				int port;
				if(sscanf(value, "%24[^:]:%i", address, &port) == 2) {
					chipvpn_address_t bind_addr;
					if(!chipvpn_address_set_ip(&bind_addr, address)) {
						return;
					}
					bind_addr.port = port;
					if(!chipvpn_udp_bind(vpn->udp, &bind_addr)) {
						return;
					}
				}
			} else if(strcmp(key, "sendbuf") == 0) {
				int sendbuf;
				if(sscanf(value, "%i", &sendbuf) == 1) {
					chipvpn_udp_set_sendbuf(vpn->udp, sendbuf);
				}
			} else if(strcmp(key, "recvbuf") == 0) {
				int recvbuf;
				if(sscanf(value, "%i", &recvbuf) == 1) {
					chipvpn_udp_set_recvbuf(vpn->udp, recvbuf);
				}
			} else if(strcmp(key, "ifup") == 0) {
				chipvpn_device_set_enabled(vpn->device);
			} else if(strcmp(key, "ifdown") == 0) {
				chipvpn_device_set_disabled(vpn->device);
			}
			continue;
		}

		/* peer section */
		if(section == COMMAND_PEER_SECTION) {
			chipvpn_peer_t *peer = (chipvpn_peer_t*)chipvpn_list_back(&vpn->device->peers);
			if(!peer) {
				continue;
			}

			if(strcmp(key, "address") == 0) {
				char address[512];
				int port;
				if(sscanf(value, "%512[^:]:%i", address, &port) == 2) {
					chipvpn_peer_set_address(peer, address, port);
				}
			} else if(strcmp(key, "allow") == 0) {
				char address[24];
				int prefix;
				if(sscanf(value, "%24[^/]/%i", address, &prefix) == 2) {
					chipvpn_peer_set_allow(peer, address, prefix);
				}
			} else if(strcmp(key, "public") == 0) {
				char pubkey[1024];
				if(sscanf(value, "%1023s", pubkey) == 1) {
					chipvpn_peer_set_public_key(peer, vpn->device, pubkey);
				}
			} else if(strcmp(key, "mss") == 0) {
				int mss;
				if(sscanf(value, "%i", &mss) == 1) {
					peer->config.firewall.mss = mss;
				}
			} else if(strcmp(key, "onconnect") == 0) {
				chipvpn_peer_set_onconnect(peer, value);
			} else if(strcmp(key, "onping") == 0) {
				chipvpn_peer_set_onping(peer, value);
			} else if(strcmp(key, "ondisconnect") == 0) {
				chipvpn_peer_set_ondisconnect(peer, value);
			}
		}
	}
}
