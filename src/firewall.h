#ifndef FIREWALL_H
#define FIREWALL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include "address.h"
#include "list.h"

typedef struct {
	chipvpn_list_node_t node;
	chipvpn_address_t net;
} chipvpn_firewall_entry_t;

bool chipvpn_firewall_init(chipvpn_list_t *list);
bool chipvpn_firewall_insert(chipvpn_list_t *list, chipvpn_address_t *net);
bool chipvpn_firewall_execute(chipvpn_list_t *list, chipvpn_address_t *address);
void chipvpn_firewall_cleanup(chipvpn_list_t *list);

#ifdef __cplusplus
}
#endif

#endif