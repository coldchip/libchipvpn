#include <signal.h>
#include "chipvpn.h"

volatile sig_atomic_t quit = 0;

void terminate(int type) {
	quit = 1;
}

int main(int argc, char const *argv[]) {
	/* code */

	signal(SIGINT, terminate);
	signal(SIGTERM, terminate);

	#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, terminate);
	signal(SIGQUIT, terminate);
	#endif

	chipvpn_address_t address;
	chipvpn_address_set_ip(&address, "10.128.0.4");
	address.prefix = 16;

	chipvpn_t *vpn = chipvpn_init(NULL);
	if(!vpn) {
		printf("unable to create vpn\n");
		exit(1);
	}

	chipvpn_tun_set_ip(vpn->tun, &address);
	chipvpn_tun_set_mtu(vpn->tun, 1400);

	chipvpn_peer_t *peer = chipvpn_peer_create();
	chipvpn_peer_set_endpoint(peer, "157.245.205.9:443");
	chipvpn_peer_set_allow(peer, "0.0.0.0/0");
	chipvpn_peer_set_key(peer, "DQpMnJgkndkrD8wVxd5noIEcJ1wWjS6bJtL6kFUoeBHclqnS0UaPjvs5UPZB0Q2n");
	chipvpn_list_insert(chipvpn_list_end(&vpn->device->peers), peer);

	chipvpn_peer_state_e current_state = PEER_DISCONNECTED;

	while(!quit) {
		chipvpn_wait(vpn);
		chipvpn_service(vpn);

		if(peer->state == PEER_DISCONNECTED) {
			chipvpn_peer_connect(peer, 10);
		}

		if(current_state != peer->state) {
			printf("change state\n");
			current_state = peer->state;
		}
	}

	printf("cleanup\n");

	chipvpn_peer_disconnect(peer, 10);

	chipvpn_cleanup(vpn);

	return 0;
}