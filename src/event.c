#include <string.h>
#include <stdlib.h>
#include "list.h"
#include "event.h"

void chipvpn_event_init(chipvpn_event_t *event) {
	chipvpn_list_clear(&event->fifo);
}

void chipvpn_event_push(chipvpn_event_t *event, chipvpn_event_type_e type, const char *message) {
	chipvpn_event_entry_t *entry = malloc(sizeof(chipvpn_event_entry_t));
	entry->type = type;
	strncpy(entry->message, message, sizeof(entry->message) - 1);

	chipvpn_list_insert(chipvpn_list_end(&event->fifo), entry);
}

chipvpn_event_entry_t *chipvpn_event_pop(chipvpn_event_t *event) {
	chipvpn_event_entry_t *entry = (chipvpn_event_entry_t*)chipvpn_list_remove(chipvpn_list_begin(&event->fifo));
	return entry;
}

int chipvpn_event_size(chipvpn_event_t *event) {
	return (int)chipvpn_list_size(&event->fifo);
}