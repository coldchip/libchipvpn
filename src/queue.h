#ifndef QUEUE_H
#define QUEUE_H

#include "address.h"

#define QUEUE_ENTRY_SIZE 8192

typedef struct {
	uint16_t size;
	chipvpn_address_t addr;
	uint8_t buffer[QUEUE_ENTRY_SIZE];
} chipvpn_queue_entry_t;

typedef struct {
    chipvpn_queue_entry_t *pool;
    int head;
    int tail;
    int size;
    int total_size;
} chipvpn_queue_t;

typedef struct {
	void *data;
	size_t size;
} chipvpn_queue_vector_t;

bool                    chipvpn_queue_init(chipvpn_queue_t *queue, int queue_size);

bool                    chipvpn_queue_can_enqueue(chipvpn_queue_t *queue);
bool                    chipvpn_queue_can_dequeue(chipvpn_queue_t *queue);

chipvpn_queue_entry_t  *chipvpn_queue_enqueue_acquire(chipvpn_queue_t *queue);
void                    chipvpn_queue_enqueue_commit(chipvpn_queue_t *queue, chipvpn_queue_entry_t *entry);
chipvpn_queue_entry_t  *chipvpn_queue_dequeue_acquire(chipvpn_queue_t *queue);
void                    chipvpn_queue_dequeue_commit(chipvpn_queue_t *queue, chipvpn_queue_entry_t *entry);

size_t                  chipvpn_queue_read(chipvpn_queue_t *queue, void *data, size_t size, chipvpn_address_t *addr);
size_t                  chipvpn_queue_write(chipvpn_queue_t *queue, void *data, size_t size, chipvpn_address_t *addr);

size_t                  chipvpn_queue_read_vector(chipvpn_queue_t *queue, chipvpn_queue_vector_t *vector, size_t size, chipvpn_address_t *addr);
size_t                  chipvpn_queue_write_vector(chipvpn_queue_t *queue, chipvpn_queue_vector_t *vector, size_t size, chipvpn_address_t *addr);

void                    chipvpn_queue_cleanup(chipvpn_queue_t *queue);

#endif