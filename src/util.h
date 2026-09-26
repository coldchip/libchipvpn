#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SECURE32 __attribute__((cleanup(chipvpn_wipe_mem_32)))

#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define MAX(x, y) (((x) > (y)) ? (x) : (y))

#if __BIG_ENDIAN__
# define htonll(x) (x)
# define ntohll(x) (x)
#else
# define htonll(x) (((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
# define ntohll(x) (((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))
#endif

#define _U8C(v) (v##U)
#define _U8V(v) ((uint8_t)(v) & _U8C(0xFF))

#define U64TO8_BIG(p, v) \
do { \
    (p)[7] = _U8V((v)      ); \
    (p)[6] = _U8V((v) >>  8); \
    (p)[5] = _U8V((v) >> 16); \
    (p)[4] = _U8V((v) >> 24); \
    (p)[3] = _U8V((v) >> 32); \
    (p)[2] = _U8V((v) >> 40); \
    (p)[1] = _U8V((v) >> 48); \
    (p)[0] = _U8V((v) >> 56); \
} while (0)

#define U32TO8_BIG(p, v) \
do { \
    (p)[3] = _U8V((v)      ); \
    (p)[2] = _U8V((v) >>  8); \
    (p)[1] = _U8V((v) >> 16); \
    (p)[0] = _U8V((v) >> 24); \
} while (0)

void         chipvpn_init_noise(uint8_t *chain_key, uint8_t *hash_key, const uint8_t *peer_pub);
void         chipvpn_compute_macs(void *packet, size_t auth_len, uint8_t *mac1, uint8_t *mac2, const uint8_t *peer_pub);
void         chipvpn_encrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t len, uint8_t *mac);
bool         chipvpn_decrypt_and_mix(uint8_t *hash_key, uint8_t *cipher_key, uint8_t *data, size_t len, uint8_t *mac);

void         chipvpn_print_key(uint8_t *key);
char        *chipvpn_strdup(const char *s);
char        *chipvpn_read_file(const char *file);
char        *chipvpn_str_replace(const char* s, const char* oldW, const char* newW);
char        *chipvpn_sgets(char *buf, int n, const char **str);
bool         chipvpn_get_gateway(char *ip, char *dev);
char        *chipvpn_format_bytes(uint64_t bytes);
bool         chipvpn_secure_random(uint8_t *buf, int size);
uint64_t     chipvpn_get_time();
int          chipvpn_secure_memcmp(const void *a, const void *b, size_t size);
void         chipvpn_secure_zero(void *v, size_t n);
bool         chipvpn_check_key_randomness(const uint8_t *key, size_t length);
void         chipvpn_tai64n(uint8_t *output);

static inline void chipvpn_wipe_mem_32(uint8_t (*key)[32]) {
    chipvpn_secure_zero(key, 32);
}

#ifdef __cplusplus
}
#endif

#endif