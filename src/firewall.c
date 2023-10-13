#include <stdbool.h>
#include <arpa/inet.h>
#include "firewall.h"
#include "packet.h"

chipvpn_firewall_t *chipvpn_firewall_create() {
	chipvpn_firewall_t *firewall = malloc(sizeof(chipvpn_firewall_t));
	if(!firewall) {
		return NULL;
	}

	chipvpn_list_clear(&firewall->outbound);
	chipvpn_list_clear(&firewall->inbound);

	return firewall;
}

bool chipvpn_firewall_validate_outbound(chipvpn_firewall_t *firewall, char *packet) {
	bool valid_address  = false;
	bool valid_port     = false;
	bool valid_protocol = false;

	ip_hdr_t *ip_hdr = (ip_hdr_t*)packet;

	for(chipvpn_list_node_t *r = chipvpn_list_begin(&firewall->outbound); r != chipvpn_list_end(&firewall->outbound); r = chipvpn_list_next(r)) {
		valid_address  = false;
		valid_port     = false;
		valid_protocol = false;

		chipvpn_firewall_rule_t *rule = (chipvpn_firewall_rule_t*)r;

		chipvpn_address_t address = {
			.ip = ip_hdr->dst_addr
		};

		if(chipvpn_address_cidr_match(&address, &rule->address)) {
			valid_address = true;
		}

		switch(rule->protocol) {
			case 6:
			case 17: {
				udp_tcp_port_t *udp_tcp_port = (udp_tcp_port_t*)(packet + (4 * ip_hdr->ihl));
				uint16_t port = ntohs(udp_tcp_port->dst);
				if(rule->start_port <= port && port <= rule->end_port) {
					valid_port = true;
				}
			}
			break;
			default: {
				valid_port = true;
			}
			break;
		}

		if(ip_hdr->ip_p == rule->protocol || rule->protocol == 255) {
			valid_protocol = true;
		}

		if(valid_address && valid_port && valid_protocol) {
			return true;
		}
	}


	return false;
}

bool chipvpn_firewall_validate_inbound(chipvpn_firewall_t *firewall, char *packet) {
	bool valid_address  = false;
	bool valid_port     = false;
	bool valid_protocol = false;

	ip_hdr_t *ip_hdr = (ip_hdr_t*)packet;

	for(chipvpn_list_node_t *r = chipvpn_list_begin(&firewall->inbound); r != chipvpn_list_end(&firewall->inbound); r = chipvpn_list_next(r)) {
		valid_address  = false;
		valid_port     = false;
		valid_protocol = false;

		chipvpn_firewall_rule_t *rule = (chipvpn_firewall_rule_t*)r;

		chipvpn_address_t address = {
			.ip = ip_hdr->src_addr
		};

		if(chipvpn_address_cidr_match(&address, &rule->address)) {
			valid_address = true;
		}

		switch(rule->protocol) {
			case 6:
			case 17: {
				udp_tcp_port_t *udp_tcp_port = (udp_tcp_port_t*)(packet + (4 * ip_hdr->ihl));
				uint16_t port = ntohs(udp_tcp_port->src);
				if(rule->start_port <= port && port <= rule->end_port) {
					valid_port = true;
				}
			}
			break;
			default: {
				valid_port = true;
			}
			break;
		}

		if(ip_hdr->ip_p == rule->protocol || rule->protocol == 255) {
			valid_protocol = true;
		}

		if(valid_address && valid_port && valid_protocol) {
			return true;
		}
	}


	return false;
}

void chipvpn_firewall_reset(chipvpn_firewall_t *firewall) {
	while(!chipvpn_list_empty(&firewall->outbound)) {
		chipvpn_firewall_rule_t *rule = (chipvpn_firewall_rule_t*)chipvpn_list_remove(chipvpn_list_begin(&firewall->outbound));
		free(rule);
	}

	while(!chipvpn_list_empty(&firewall->inbound)) {
		chipvpn_firewall_rule_t *rule = (chipvpn_firewall_rule_t*)chipvpn_list_remove(chipvpn_list_begin(&firewall->inbound));
		free(rule);
	}
}

void chipvpn_firewall_free(chipvpn_firewall_t *firewall) {
	chipvpn_firewall_reset(firewall);
	free(firewall);
}