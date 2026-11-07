#ifndef TIMER_H
#define TIMER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * timer heap: a binary min-heap of timers ordered by expiry, the root is
 * always the timer that expires first.
 *
 *   find the earliest timer          O(1)
 *   schedule, reschedule or cancel   O(log n)
 *
 * a timer is embedded in the struct that owns it (e.g. chipvpn_peer_t) and
 * remembers its own position in the heap, so it can be moved or cancelled
 * without searching. all times are absolute milliseconds of chipvpn_get_time().
 */

/* expiry of a timer that never fires */
#define CHIPVPN_TIMER_NEVER UINT64_MAX

/* heap index of a timer that is not scheduled */
#define CHIPVPN_TIMER_IDLE SIZE_MAX

/* get the struct that embeds a timer, e.g. chipvpn_timer_entry(timer, chipvpn_peer_t, timer) */
#define chipvpn_timer_entry(timer, type, member) ((type *)((char *)(timer) - offsetof(type, member)))

typedef struct {
	/* absolute time at which the timer fires */
	uint64_t expiry;
	/* position in the heap, CHIPVPN_TIMER_IDLE when not scheduled */
	size_t index;
} chipvpn_timer_t;

typedef struct {
	/* heap array, timers[0] expires first */
	chipvpn_timer_t **timers;
	size_t size;
	size_t capacity;
} chipvpn_timer_heap_t;

void                    chipvpn_timer_heap_init(chipvpn_timer_heap_t *heap);
void                    chipvpn_timer_heap_cleanup(chipvpn_timer_heap_t *heap);

void                    chipvpn_timer_init(chipvpn_timer_t *timer);
bool                    chipvpn_timer_pending(const chipvpn_timer_t *timer);
bool                    chipvpn_timer_schedule(chipvpn_timer_heap_t *heap, chipvpn_timer_t *timer, uint64_t expiry);
void                    chipvpn_timer_cancel(chipvpn_timer_heap_t *heap, chipvpn_timer_t *timer);

chipvpn_timer_t        *chipvpn_timer_pop_expired(chipvpn_timer_heap_t *heap, uint64_t now);
uint64_t                chipvpn_timer_timeout(const chipvpn_timer_heap_t *heap, uint64_t now);

#ifdef __cplusplus
}
#endif

#endif
