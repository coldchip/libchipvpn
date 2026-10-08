#ifndef SOCKET_H
#define SOCKET_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/select.h>
#include <unistd.h>
#include "address.h"

#define SOCKET_QUEUE_SIZE 64
#define SOCKET_QUEUE_ENTRY_SIZE 16384

_Static_assert((SOCKET_QUEUE_SIZE & (SOCKET_QUEUE_SIZE - 1)) == 0, 
               "SOCKET_QUEUE_SIZE must be a power of 2");

typedef enum {
	CHIPVPN_SOCKET_DGRAM = 0,
	CHIPVPN_SOCKET_STREAM = 1
} chipvpn_socket_type_e;

typedef struct {
	bool is_used;
	uint16_t size;
	chipvpn_address_t addr;
	uint8_t buffer[SOCKET_QUEUE_ENTRY_SIZE];
} chipvpn_socket_queue_entry_t;

typedef struct {
    chipvpn_socket_queue_entry_t pool[SOCKET_QUEUE_SIZE];
    int head;
    int tail;
    int size;
} chipvpn_socket_queue_t;

typedef struct {
	void *data;
	size_t size;
} chipvpn_socket_vector_t;

typedef struct {
	int fd;
	chipvpn_socket_queue_t tx_queue;
	chipvpn_socket_queue_t rx_queue;
	chipvpn_socket_type_e type;

	void (*tx_transform) (void *transform_data, uint8_t *out, size_t *out_size, uint8_t *in, size_t in_size);
	void (*rx_transform) (void *transform_data, uint8_t *out, size_t *out_size, uint8_t *in, size_t in_size);
	void *transform_data;
} chipvpn_socket_t;



chipvpn_socket_t                *chipvpn_socket_create(int fd, int type);

bool                             chipvpn_socket_raw_read(chipvpn_socket_t *sock, chipvpn_socket_queue_entry_t *entry);
bool                             chipvpn_socket_raw_write(chipvpn_socket_t *sock, chipvpn_socket_queue_entry_t *entry);

void                             chipvpn_socket_preselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset, int *max);
void                             chipvpn_socket_postselect(chipvpn_socket_t *sock, fd_set *rdset, fd_set *wdset);
void                             chipvpn_socket_postselect_rdset(chipvpn_socket_t *sock, fd_set *rdset);
void                             chipvpn_socket_postselect_wdset(chipvpn_socket_t *sock, fd_set *wdset);

void                             chipvpn_socket_reset_queue(chipvpn_socket_queue_t *queue);

chipvpn_socket_queue_entry_t    *chipvpn_socket_enqueue_acquire(chipvpn_socket_queue_t *queue);
chipvpn_socket_queue_entry_t    *chipvpn_socket_dequeue_acquire(chipvpn_socket_queue_t *queue);
void                             chipvpn_socket_enqueue_commit(chipvpn_socket_queue_t *queue, chipvpn_socket_queue_entry_t *entry);
void                             chipvpn_socket_dequeue_commit(chipvpn_socket_queue_t *queue, chipvpn_socket_queue_entry_t *entry);

chipvpn_socket_queue_entry_t    *chipvpn_socket_available_entry(chipvpn_socket_queue_t *queue);

bool                             chipvpn_socket_can_enqueue(chipvpn_socket_t *sock);
bool                             chipvpn_socket_can_dequeue(chipvpn_socket_t *sock);
bool                             chipvpn_socket_can_read(chipvpn_socket_t *sock);
bool                             chipvpn_socket_can_write(chipvpn_socket_t *sock);

size_t                           chipvpn_socket_read(chipvpn_socket_t *sock, void *data, size_t size, chipvpn_address_t *addr);
size_t                           chipvpn_socket_write(chipvpn_socket_t *sock, void *data, size_t size, chipvpn_address_t *addr);

size_t                           chipvpn_socket_read_vector(chipvpn_socket_t *sock, chipvpn_socket_vector_t *vector, size_t size, chipvpn_address_t *addr);
size_t                           chipvpn_socket_write_vector(chipvpn_socket_t *sock, chipvpn_socket_vector_t *vector, size_t size, chipvpn_address_t *addr);

void                             chipvpn_socket_free(chipvpn_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif