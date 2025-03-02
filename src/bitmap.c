#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "util.h"
#include "bitmap.h"

void chipvpn_bitmap_reset(chipvpn_bitmap_t *window) {
	window->counter = 0l;
	memset(window, 0, sizeof(chipvpn_bitmap_t));
}


bool chipvpn_bitmap_validate(chipvpn_bitmap_t *window, uint64_t counter) {
    if(
    	(window->counter >= REJECT_AFTER_MESSAGES + 1) ||
		(counter >= REJECT_AFTER_MESSAGES)
	) {
    	return false;
	}

	counter++;

    if((COUNTER_WINDOW_SIZE + counter) < window->counter) {
		return false;
    }

    uint64_t index = (counter >> LOG2_64);

	if(counter > window->counter) {
	    uint64_t index_cur = window->counter >> LOG2_64;
	    uint64_t top = MIN(index - index_cur, COUNTER_BITS_TOTAL / U64_SIZE);

	    for(uint64_t i = 1; i <= top; ++i) {
	        window->bitmap[(i + index_cur) & ((COUNTER_BITS_TOTAL / U64_SIZE) - 1)] = 0;
	    }

	    window->counter = counter;
	}

    index &= (COUNTER_BITS_TOTAL / U64_SIZE) - 1;

    if(window->bitmap[index] & (1ULL << (counter & (U64_SIZE - 1)))) {
    	return false;
	}

    window->bitmap[index] |= (1ULL << (counter & (U64_SIZE - 1)));
    return true;
}