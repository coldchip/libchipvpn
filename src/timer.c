#include "timer.h"
#include <stdlib.h>

/* heap layout: the parent of index i is (i - 1) / 2, its children are 2i + 1 and 2i + 2 */

static bool chipvpn_timer_before(const chipvpn_timer_heap_t *heap, size_t a, size_t b) {
	return heap->timers[a]->expiry < heap->timers[b]->expiry;
}

static void chipvpn_timer_swap(chipvpn_timer_heap_t *heap, size_t a, size_t b) {
	chipvpn_timer_t *tmp = heap->timers[a];
	heap->timers[a] = heap->timers[b];
	heap->timers[b] = tmp;

	/* timers track their own position */
	heap->timers[a]->index = a;
	heap->timers[b]->index = b;
}

/* move a timer towards the root while it expires before its parent */
static void chipvpn_timer_sift_up(chipvpn_timer_heap_t *heap, size_t index) {
	while(index > 0) {
		size_t parent = (index - 1) / 2;

		if(!chipvpn_timer_before(heap, index, parent)) {
			break;
		}

		chipvpn_timer_swap(heap, index, parent);
		index = parent;
	}
}

/* move a timer towards the leaves while one of its children expires before it */
static void chipvpn_timer_sift_down(chipvpn_timer_heap_t *heap, size_t index) {
	while(true) {
		size_t left     = 2 * index + 1;
		size_t right    = 2 * index + 2;
		size_t earliest = index;

		if(left < heap->size && chipvpn_timer_before(heap, left, earliest)) {
			earliest = left;
		}

		if(right < heap->size && chipvpn_timer_before(heap, right, earliest)) {
			earliest = right;
		}

		if(earliest == index) {
			break;
		}

		chipvpn_timer_swap(heap, index, earliest);
		index = earliest;
	}
}

/* restore heap order after a timer was added, moved or given a new expiry (only one of the two sifts moves it) */
static void chipvpn_timer_fix(chipvpn_timer_heap_t *heap, chipvpn_timer_t *timer) {
	chipvpn_timer_sift_up(heap, timer->index);
	chipvpn_timer_sift_down(heap, timer->index);
}

void chipvpn_timer_heap_init(chipvpn_timer_heap_t *heap) {
	/* the array is allocated on the first schedule */
	heap->timers   = NULL;
	heap->size     = 0;
	heap->capacity = 0;
}

void chipvpn_timer_heap_cleanup(chipvpn_timer_heap_t *heap) {
	/* any timer still in the heap becomes idle */
	for(size_t i = 0; i < heap->size; i++) {
		heap->timers[i]->index = CHIPVPN_TIMER_IDLE;
	}

	free(heap->timers);
	chipvpn_timer_heap_init(heap);
}

void chipvpn_timer_init(chipvpn_timer_t *timer) {
	timer->expiry = CHIPVPN_TIMER_NEVER;
	timer->index  = CHIPVPN_TIMER_IDLE;
}

bool chipvpn_timer_pending(const chipvpn_timer_t *timer) {
	return timer->index != CHIPVPN_TIMER_IDLE;
}

bool chipvpn_timer_schedule(chipvpn_timer_heap_t *heap, chipvpn_timer_t *timer, uint64_t expiry) {
	if(!chipvpn_timer_pending(timer)) {
		/* grow the array when full, this is the only allocation the heap makes */
		if(heap->size == heap->capacity) {
			size_t capacity = heap->capacity > 0 ? heap->capacity * 2 : 16;

			chipvpn_timer_t **timers = realloc(heap->timers, capacity * sizeof(chipvpn_timer_t*));
			if(!timers) {
				return false;
			}

			heap->timers   = timers;
			heap->capacity = capacity;
		}

		/* append as the last leaf */
		timer->index = heap->size;
		heap->timers[heap->size++] = timer;
	}

	timer->expiry = expiry;
	chipvpn_timer_fix(heap, timer);

	return true;
}

void chipvpn_timer_cancel(chipvpn_timer_heap_t *heap, chipvpn_timer_t *timer) {
	if(!chipvpn_timer_pending(timer)) {
		return;
	}

	size_t index = timer->index;
	size_t last  = heap->size - 1;

	/* fill the hole with the last leaf, then drop the last slot */
	if(index != last) {
		chipvpn_timer_swap(heap, index, last);
	}

	heap->size--;
	timer->index = CHIPVPN_TIMER_IDLE;

	/* the moved leaf may belong higher or lower than the hole */
	if(index < heap->size) {
		chipvpn_timer_fix(heap, heap->timers[index]);
	}
}

chipvpn_timer_t *chipvpn_timer_pop_expired(chipvpn_timer_heap_t *heap, uint64_t now) {
	/* the root expires first, if it hasn't expired nothing has */
	if(heap->size == 0 || heap->timers[0]->expiry > now) {
		return NULL;
	}

	chipvpn_timer_t *timer = heap->timers[0];
	chipvpn_timer_cancel(heap, timer);

	return timer;
}

uint64_t chipvpn_timer_timeout(const chipvpn_timer_heap_t *heap, uint64_t now) {
	/* milliseconds until the earliest timer fires, 0 if it is already due */
	if(heap->size == 0) {
		return CHIPVPN_TIMER_NEVER;
	}

	uint64_t expiry = heap->timers[0]->expiry;

	return expiry > now ? expiry - now : 0;
}
