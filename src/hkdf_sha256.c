#include "hkdf_sha256.h"
#include "hmac_sha256.h"
#include <string.h>

enum {
    DIGEST_SIZE = 32,
    BLOCK_SIZE = 64,
};

enum {
    shaBadParam = 13,
    SUCCESS = 0,
    FAILURE = 1,
};

/*
 * ikm = initial keying material
 * prk = pseudo-random key (that will be used in the next step)
 */
int hkdf_extract(const unsigned char *salt, size_t salt_length,
                 const unsigned char *ikm, size_t ikm_length,
                 unsigned char *prk, size_t prk_length) {
    static unsigned char null_salt[DIGEST_SIZE] = {0};

    /* RFC 5869 - 2.2
     * salt     optional salt value (a non-secret random value);
     *          if not provided, it is set to a string of HashLen zeros. */
    if (salt == NULL || salt_length == 0) {
        salt = null_salt;
        salt_length = DIGEST_SIZE;
    }

    /* RFC 5869 - 2.2
     * The output PRK is calculated as follows:
     * PRK = HMAC-Hash(salt, IKM) */
    hmac_sha256(salt, salt_length, /* key */
                       ikm, ikm_length,   /* msg */
                       prk, prk_length    /* digest */
    );
    return SUCCESS;
}
/*
 * @param okm_length
 *  This is the value of 'L', the desired number of bytes to
 *  expand to.
 */
int hkdf_expand(const unsigned char *prk, size_t prk_len,
                const unsigned char *info, size_t info_len, unsigned char *okm,
                size_t okm_len) {
    size_t n;
    size_t offset = 0;
    size_t N;
    size_t T_length;
    unsigned char T[DIGEST_SIZE];

    /* RFC 5869 - 2.3
     * PRK      a pseudorandom key of at least HashLen octets
     *          (usually, the output from the extract step)
     */
    if (prk_len < DIGEST_SIZE)
        return FAILURE;

    /* RFC 5869 - 2.3
     * info     optional ctx and application specific information
     *         (can be a zero-length string) */
    if (info == NULL || info_len == 0) {
        info = (const unsigned char *)"";
        info_len = 0;
    }

    /* RFC 5869 - 2.3
     *     L        length of output keying material in octets
     *          (<= 255*HashLen) */
    if (okm_len > 255 * DIGEST_SIZE)
        return FAILURE;

    /* N = ceil(L/HashLen) */
    N = okm_len / DIGEST_SIZE;
    if ((okm_len % DIGEST_SIZE) != 0)
        N++;

    /* T(0) = empty string (zero length) */
    T_length = 0;

    /*
     * T(n) = HMAC-Hash(PRK, T(n-1) | info | n)
     * (where the constant concatenated to the end of each T(n) is a
     * single octet.)
     */
    for (n = 1; n <= N; n++) {
        HMAC_CTX ctx;
        unsigned char c = n;
        size_t j;

        hmac_sha256_init(&ctx, prk, prk_len);
        hmac_sha256_update(&ctx, T, T_length);
        hmac_sha256_update(&ctx, info, info_len);
        hmac_sha256_update(&ctx, &c, 1);
        hmac_sha256_final(&ctx, T, DIGEST_SIZE);

        /* T = T(1) | T(2) | T(3) | ... | T(N)
         * OKM = first L octets of T */
        for (j = 0; j < DIGEST_SIZE && offset + j < okm_len; j++)
            okm[offset + j] = T[j];

        offset += DIGEST_SIZE;
        T_length = DIGEST_SIZE;
    }
    return SUCCESS;
}

int hkdf_sha256(const void *salt, size_t salt_length, const void *ikm,
                size_t ikm_length, const void *info, size_t info_len,
                unsigned char *okm, size_t okm_len) {
    int err;
    unsigned char prk[DIGEST_SIZE];

    err = hkdf_extract(salt, salt_length, ikm, ikm_length, prk, sizeof(prk));
    if (err != SUCCESS)
        return err;

    err = hkdf_expand(prk, DIGEST_SIZE, info, info_len, okm, okm_len);
    if (err != SUCCESS)
        return err;

    return SUCCESS;
}