#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "util.h"
#include "address.h"
#include "ratelimit.h"

uint32_t chipvpn_ratelimit_hash_addr(chipvpn_address_t *addr) {
    uint64_t key = 0;

    if(addr->type == CHIPVPN_ADDRESS_IPV6) {
        /* /64 mask */
        memcpy(&key, addr->ipv6, 8);
    } else {
        key = addr->ipv4;
    }

    /* MurmurHash3 64-bit finalizer */
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccdULL;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53ULL;
    key ^= key >> 33;

    return (uint32_t)key & (CHIPVPN_RATELIMIT_SIZE - 1);
}

static bool chipvpn_ratelimit_match(chipvpn_address_t *a, chipvpn_address_t *b) {
    if(a->type != b->type) {
        return false;
    }

    if(a->type == CHIPVPN_ADDRESS_IPV6) {
        /* Match the /64 prefix (first 8 bytes) */
        return memcmp(a->ipv6, b->ipv6, 8) == 0;
    }

    return a->ipv4 == b->ipv4;
}

void chipvpn_ratelimit_clear(chipvpn_ratelimit_t *ratelimit) {
    memset(ratelimit, 0, sizeof(chipvpn_ratelimit_t));
}

bool chipvpn_ratelimit_verify(chipvpn_ratelimit_t *ratelimit, chipvpn_address_t *addr) {
    uint64_t now = chipvpn_get_time();

    uint32_t idx = chipvpn_ratelimit_hash_addr(addr);

    chipvpn_ratelimit_entry_t *entry = &ratelimit->map[idx];

    if(entry->last_update == 0 || !chipvpn_ratelimit_match(&entry->addr, addr)) {
        entry->addr = *addr;
        entry->tokens = CHIPVPN_RATELIMIT_MAX_TOKENS;
        entry->last_update = now;
    }

    uint64_t elapsed = now - entry->last_update;
    uint64_t new_tokens = elapsed / CHIPVPN_RATELIMIT_REFILL_MS;

    if(new_tokens > 0) {
        entry->tokens += new_tokens;
        if(entry->tokens > CHIPVPN_RATELIMIT_MAX_TOKENS) {
            entry->tokens = CHIPVPN_RATELIMIT_MAX_TOKENS;
        }

        entry->last_update += new_tokens * CHIPVPN_RATELIMIT_REFILL_MS;
    }

    if(entry->tokens > 0) {
        entry->tokens--;
        return true;
    }

    return false;
}