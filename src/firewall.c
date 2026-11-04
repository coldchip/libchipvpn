#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "address.h"
#include "firewall.h"
#include "list.h"

bool chipvpn_firewall_init(chipvpn_list_t *list) {
	chipvpn_list_clear(list);
	return true;
}

bool chipvpn_firewall_insert(chipvpn_list_t *list, chipvpn_address_t *net) {
	if(list == NULL || net == NULL) {
		return false;
	}

	chipvpn_firewall_entry_t *entry = (chipvpn_firewall_entry_t*)malloc(sizeof(chipvpn_firewall_entry_t));
	if(entry == NULL) {
		return false;
	}

	memcpy(&entry->net, net, sizeof(chipvpn_address_t));

	chipvpn_list_insert(chipvpn_list_end(list), entry);

	return true;
}

bool chipvpn_firewall_execute(chipvpn_list_t *list, chipvpn_address_t *address) {
	if(list == NULL || address == NULL) {
		return false;
	}

	for(chipvpn_list_node_t *it = chipvpn_list_begin(list); it != chipvpn_list_end(list); it = chipvpn_list_next(it)) {
		chipvpn_firewall_entry_t *entry = (chipvpn_firewall_entry_t*)it;

		if(chipvpn_address_cidr_match(&entry->net, address)) {
			return true;
		}
	}

	return false;
}

void chipvpn_firewall_cleanup(chipvpn_list_t *list) {
	while(!chipvpn_list_empty(list)) {
		chipvpn_firewall_entry_t *entry = (chipvpn_firewall_entry_t*)chipvpn_list_remove(chipvpn_list_begin(list));
		free(entry);
	}
}