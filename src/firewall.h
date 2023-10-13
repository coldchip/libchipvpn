#ifndef FIREWALL_H
#define FIREWALL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include "list.h"
#include "address.h"
#include "packet.h"

typedef struct {
	chipvpn_list_node_t node;
	chipvpn_address_t address;
	uint8_t protocol;
	uint16_t start_port;
	uint16_t end_port;
} chipvpn_firewall_rule_t;

typedef struct {
	chipvpn_list_t inbound;
	chipvpn_list_t outbound;
} chipvpn_firewall_t;

chipvpn_firewall_t  *chipvpn_firewall_create();
bool                 chipvpn_firewall_validate_outbound(chipvpn_firewall_t *firewall, char *packet);
bool                 chipvpn_firewall_validate_inbound(chipvpn_firewall_t *firewall, char *packet);
void                 chipvpn_firewall_reset(chipvpn_firewall_t *firewall);
void                 chipvpn_firewall_free(chipvpn_firewall_t *firewall);

#ifdef __cplusplus
}
#endif

#endif