#include "queue.h"
#include "util.h"
#include <stdlib.h>

bool chipvpn_queue_init(chipvpn_queue_t *queue, int queue_size) {
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

bool chipvpn_queue_can_enqueue(chipvpn_queue_t *queue) {
	return queue->size < queue->total_size;
}

bool chipvpn_queue_can_dequeue(chipvpn_queue_t *queue) {
	return queue->size > 0;
}

chipvpn_queue_entry_t *chipvpn_queue_enqueue_acquire(chipvpn_queue_t *queue) {
    if(queue->size >= queue->total_size) {
    	return NULL;
    }
    return &queue->pool[queue->tail];
}

void chipvpn_queue_enqueue_commit(chipvpn_queue_t *queue, chipvpn_queue_entry_t *entry) {
    queue->tail = (queue->tail + 1) & (queue->total_size - 1);
    queue->size++;
}

chipvpn_queue_entry_t *chipvpn_queue_dequeue_acquire(chipvpn_queue_t *queue) {
    if(queue->size == 0) {
    	return NULL;
    }
    return &queue->pool[queue->head];
}

void chipvpn_queue_dequeue_commit(chipvpn_queue_t *queue, chipvpn_queue_entry_t *entry) {
    queue->head = (queue->head + 1) & (queue->total_size - 1);
    queue->size--;
}

size_t chipvpn_queue_read(chipvpn_queue_t *queue, void *data, size_t size, chipvpn_address_t *addr) {
	chipvpn_queue_vector_t vector[1] = {{
		.data = data,
		.size = size
	}};

	return chipvpn_queue_read_vector(queue, vector, 1, addr);
}

size_t chipvpn_queue_write(chipvpn_queue_t *queue, void *data, size_t size, chipvpn_address_t *addr) {
	chipvpn_queue_vector_t vector[1] = {{
		.data = data,
		.size = size
	}};

	return chipvpn_queue_write_vector(queue, vector, 1, addr);
}

size_t chipvpn_queue_read_vector(chipvpn_queue_t *queue, chipvpn_queue_vector_t *vector, size_t size, chipvpn_address_t *addr) {
	chipvpn_queue_entry_t *entry = chipvpn_queue_dequeue_acquire(queue);
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

	chipvpn_queue_dequeue_commit(queue, entry);

	return r;
}

size_t chipvpn_queue_write_vector(chipvpn_queue_t *queue, chipvpn_queue_vector_t *vector, size_t size, chipvpn_address_t *addr) {
	chipvpn_queue_entry_t *entry = chipvpn_queue_enqueue_acquire(queue);
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

	chipvpn_queue_enqueue_commit(queue, entry);

	return w;
}

void chipvpn_queue_cleanup(chipvpn_queue_t *queue) {
	free(queue->pool);
}