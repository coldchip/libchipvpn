#ifndef EVENT_H
#define EVENT_H

#include "list.h"

typedef enum {
	CHIPVPN_EVENT_CONNECT = 0,
	CHIPVPN_EVENT_DISCONNECT,
	CHIPVPN_EVENT_REJECTED,
} chipvpn_event_type_e;

typedef struct {
	chipvpn_list_node_t node;
	chipvpn_event_type_e type;
	char message[1024];
} chipvpn_event_entry_t;

typedef struct {
	chipvpn_list_t fifo;
	int max;
} chipvpn_event_t;

void                      chipvpn_event_init(chipvpn_event_t *event);
void                      chipvpn_event_push(chipvpn_event_t *event, chipvpn_event_type_e type, const char *message);
chipvpn_event_entry_t    *chipvpn_event_pop(chipvpn_event_t *event);
int                       chipvpn_event_size(chipvpn_event_t *event);

#endif