#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <stdint.h>
#include "address.h"

#define CHIPVPN_RATELIMIT_SIZE 16384 
#define CHIPVPN_RATELIMIT_MAX_TOKENS 3
#define CHIPVPN_RATELIMIT_REFILL_MS 500

typedef struct {
    chipvpn_address_t addr;
    uint64_t tokens;
    uint64_t last_update;
} chipvpn_ratelimit_entry_t;

typedef struct {
	chipvpn_ratelimit_entry_t map[CHIPVPN_RATELIMIT_SIZE];
} chipvpn_ratelimit_t;

uint32_t   chipvpn_ratelimit_hash_ip(uint32_t ip);
bool       chipvpn_ratelimit_verify(chipvpn_ratelimit_t *ratelimit, chipvpn_address_t addr);

#endif