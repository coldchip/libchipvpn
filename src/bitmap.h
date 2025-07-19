#ifndef BITMAP_H
#define BITMAP_H

#ifdef __cplusplus 
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#define U64_SIZE 64
#define COUNTER_BITS_TOTAL 8192
#define LOG2_64 6

#define COUNTER_WINDOW_SIZE COUNTER_BITS_TOTAL - U64_SIZE
#define REJECT_AFTER_MESSAGES ((uint64_t)~0ULL) - COUNTER_WINDOW_SIZE - 1

typedef struct {
    uint64_t counter;
    uint64_t bitmap[COUNTER_BITS_TOTAL / U64_SIZE];
} chipvpn_bitmap_t;

void      chipvpn_bitmap_reset(chipvpn_bitmap_t *window);
bool      chipvpn_bitmap_validate(chipvpn_bitmap_t *window, uint64_t counter);

#ifdef __cplusplus 
}
#endif 

#endif