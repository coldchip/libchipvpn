#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "chipvpn.h"
#include "queue.h"
#include "list.h"

chipvpn_queue_t *chipvpn_queue_create() {
	chipvpn_queue_t *queue = malloc(sizeof(chipvpn_queue_t));
	chipvpn_list_clear(&queue->pipe);
	return queue;
}

bool chipvpn_queue_can_read(chipvpn_queue_t *queue) {
	return chipvpn_list_size(&queue->pipe) > 0;
}

bool chipvpn_queue_can_write(chipvpn_queue_t *queue) {
	return chipvpn_list_size(&queue->pipe) < 16;
}

int chipvpn_queue_write(chipvpn_queue_t *queue, void *data, int size, chipvpn_address_t *address) {
	chipvpn_queue_entry_t *entry = malloc(sizeof(chipvpn_queue_entry_t) + size);
	entry->size = size;
	if(address) {
		entry->address = *address;
	}
	memcpy(((char*)entry) + sizeof(chipvpn_queue_entry_t), data, size);

	chipvpn_list_insert(chipvpn_list_end(&queue->pipe), entry);

	return size;
}

int chipvpn_queue_read(chipvpn_queue_t *queue, void *data, int size, chipvpn_address_t *address) {
	if(!chipvpn_list_empty(&queue->pipe)) {
		chipvpn_queue_entry_t *entry = (chipvpn_queue_entry_t*)chipvpn_list_remove(chipvpn_list_begin(&queue->pipe));

		size = MIN(size, entry->size);

		if(address) {
			*address = entry->address;
		}

		memcpy(data, ((char*)entry) + sizeof(chipvpn_queue_entry_t), size);

		free(entry);

		return size;
	}
	return 0;
}

void chipvpn_queue_free(chipvpn_queue_t *queue) {
	while(!chipvpn_list_empty(&queue->pipe)) {
		chipvpn_queue_entry_t *entry = (chipvpn_queue_entry_t*)chipvpn_list_remove(chipvpn_list_begin(&queue->pipe));
		free(entry);
	}

	free(queue);
}