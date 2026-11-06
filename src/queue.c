#include "queue.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>

bool chipvpn_queue_init(chipvpn_queue_t *queue, size_t queue_size) {
	if(queue_size == 0 || (queue_size & (queue_size - 1)) != 0) {
		return false;
	}

	queue->head = 0;
	queue->tail = 0;
	queue->size = 0;
	queue->total_size = queue_size;

	queue->pool = malloc(queue_size * sizeof(chipvpn_queue_entry_t));
	if(!queue->pool) {
		return false;
	}

	return true;
}

chipvpn_queue_entry_t *chipvpn_queue_push_acquire(const chipvpn_queue_t *queue) {
	if(queue->size >= queue->total_size) {
		return NULL;
	}
	return &queue->pool[queue->tail];
}

chipvpn_queue_entry_t *chipvpn_queue_pop_acquire(const chipvpn_queue_t *queue) {
	if(queue->size == 0) {
		return NULL;
	}
	return &queue->pool[queue->head];
}

void chipvpn_queue_push_commit(chipvpn_queue_t *queue, chipvpn_queue_entry_t *entry) {
	queue->tail = (queue->tail + 1) & (queue->total_size - 1);
	queue->size++;
}

void chipvpn_queue_pop_commit(chipvpn_queue_t *queue, chipvpn_queue_entry_t *entry) {
	queue->head = (queue->head + 1) & (queue->total_size - 1);
	queue->size--;
}

size_t chipvpn_queue_push(chipvpn_queue_t *queue, void *data, size_t size, const chipvpn_address_t *addr) {
	chipvpn_queue_vector_t vector[1] = {{
		.data = data,
		.size = size
	}};

	return chipvpn_queue_push_vector(queue, vector, 1, addr);
}

size_t chipvpn_queue_pop(chipvpn_queue_t *queue, void *data, size_t size, chipvpn_address_t *addr) {
	chipvpn_queue_vector_t vector[1] = {{
		.data = data,
		.size = size
	}};

	return chipvpn_queue_pop_vector(queue, vector, 1, addr);
}

size_t chipvpn_queue_push_vector(chipvpn_queue_t *queue, chipvpn_queue_vector_t *vector, size_t size, const chipvpn_address_t *addr) {
	chipvpn_queue_entry_t *entry = chipvpn_queue_push_acquire(queue);
	if(entry == NULL) {
		return 0;
	}

	if(addr) {
		entry->addr = *addr;
	}

	size_t w = 0;
	for(size_t i = 0; i < size; i++) {
		size_t chunk_size = MIN(vector[i].size, sizeof(entry->buffer) - w);
		memcpy(entry->buffer + w, vector[i].data, chunk_size);
		w += chunk_size;
	}

	entry->size = (uint16_t)w;

	chipvpn_queue_push_commit(queue, entry);

	return w;
}

size_t chipvpn_queue_pop_vector(chipvpn_queue_t *queue, chipvpn_queue_vector_t *vector, size_t size, chipvpn_address_t *addr) {
	chipvpn_queue_entry_t *entry = chipvpn_queue_pop_acquire(queue);
	if(entry == NULL) {
		return 0;
	}

	if(addr) {
		*addr = entry->addr;
	}

	size_t r = 0;
	for(size_t i = 0; i < size; i++) {
		size_t chunk_size = MIN(vector[i].size, entry->size - r);
		memcpy(vector[i].data, entry->buffer + r, chunk_size);
		r += chunk_size;
	}

	entry->size = 0;

	chipvpn_queue_pop_commit(queue, entry);

	return r;
}

void chipvpn_queue_cleanup(chipvpn_queue_t *queue) {
	free(queue->pool);
}