#include <stdbool.h>
#include <time.h>
#include "log.h"
#include "util.h"
#include "address.h"
#include "ratelimit.h"

uint32_t chipvpn_ratelimit_hash_ip(uint32_t ip) {
    ip ^= ip >> 16;
    ip *= 0x85ebca6b;
    ip ^= ip >> 13;
    ip *= 0xc2b2ae35;
    ip ^= ip >> 16;
    return ip & (CHIPVPN_RATELIMIT_SIZE - 1);
}

bool chipvpn_ratelimit_verify(chipvpn_ratelimit_t *ratelimit, chipvpn_address_t addr) {
    uint64_t now = chipvpn_get_time();
    
    uint32_t idx = chipvpn_ratelimit_hash_ip(addr.ip);

    chipvpn_ratelimit_entry_t *entry = &ratelimit->map[idx];

    if(entry->addr.ip != addr.ip) {
        entry->addr = addr;
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