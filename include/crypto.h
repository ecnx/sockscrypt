/* ------------------------------------------------------------------
 * SC Crypto - Library Source
 * ------------------------------------------------------------------ */

#ifndef SC_CRYPTO_LIB_H
#define SC_CRYPTO_LIB_H

#include <mbedtls/aes.h>

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#define AES256_KEYLEN 32
#define AES256_KEYLEN_BITS (AES256_KEYLEN * 8)
#define AES256_BLOCKLEN 16
#define PERS_STRING "SCCrypt"
#define FS_BLOCKLEN 4096

/**
 * SC random generator
 */
struct sc_random_t
{
    int initialized;
    int fd;
};

/**
 * SC context structure
 */
struct sc_context_t
{
    int initialized;
    int derive_n_rounds;
    struct sc_random_t random;
    uint8_t aeskey[AES256_KEYLEN];
};

#define SC_STREAM_INITIALIZED      1
#define SC_STREAM_ERROR_STATE      2
#define SC_STREAM_ENCRYPT_MODE     4
#define SC_STREAM_SENT_TXNONCE     8
#define SC_STREAM_RECV_RXNONCE     16

/**
 * SC stream context
 */
struct sc_stream_t
{
    int flags;
    mbedtls_aes_context aes;
    uint8_t iv[AES256_BLOCKLEN];
    int expected_len;
    uint8_t unconsumed[AES256_BLOCKLEN];
    int unconsumed_len;
    uint8_t *processed;
    int processed_size;
    int processed_len;
};

/**
 * Initialize SC context
 */
extern int sc_init ( struct sc_context_t *context, const uint8_t * key, size_t keylen );

/**
 * Uninitialize SC context
 */
extern void sc_free ( struct sc_context_t *context );

/**
 * Create new SC stream
 */
extern int sc_new_stream ( struct sc_stream_t *stream, struct sc_context_t *context, int encrypt );

/**
 * Process traffic data
 */
extern int sc_process_data ( struct sc_stream_t *stream, const uint8_t * src, int len );

/**
 * Uninitialize SC stream
 */
extern void sc_free_stream ( struct sc_stream_t *stream );

#endif
