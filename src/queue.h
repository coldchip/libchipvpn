#ifndef QUEUE_H
#define QUEUE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "address.h"
#include "list.h"


typedef struct {
	chipvpn_list_t pipe;
} chipvpn_queue_t;

typedef struct {
	chipvpn_list_node_t node;
	int size;
	chipvpn_address_t address;
} chipvpn_queue_entry_t;

chipvpn_queue_t   *chipvpn_queue_create();
bool               chipvpn_queue_can_read(chipvpn_queue_t *queue);
bool               chipvpn_queue_can_write(chipvpn_queue_t *queue);
int                chipvpn_queue_write(chipvpn_queue_t *queue, void *data, int size, chipvpn_address_t *address);
int                chipvpn_queue_read(chipvpn_queue_t *queue, void *data, int size, chipvpn_address_t *address);
void               chipvpn_queue_free(chipvpn_queue_t *queue);

#ifdef __cplusplus
}
#endif

#endif