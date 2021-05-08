/* ------------------------------------------------------------------
 * SC Crypto - Library Source
 * ------------------------------------------------------------------ */

#include "proxy.h"

/**
 * Initialize random generator wrapper
 */
static int sc_random_init ( struct sc_random_t *random )
{
    random->initialized = FALSE;

    if ( ( random->fd = open ( "/dev/urandom", O_RDONLY ) ) < 0 )
    {
        return -1;
    }

    random->initialized = TRUE;
    return 0;
}

/**
 * Read complete block of data from file
 */
static int read_complete ( int fd, uint8_t * arr, size_t len )
{
    size_t ret;
    size_t sum;

    for ( sum = 0; sum < len; sum += ret )
    {
        if ( ( ssize_t ) ( ret = read ( fd, arr + sum, len - sum ) ) <= 0 )
        {
            return -1;
        }
    }

    return 0;
}

/**
 * Generate random bytes with random generator wrapper
 */
static int sc_random_bytes ( struct sc_random_t *random, uint8_t * buf, size_t len )
{
    if ( !random->initialized )
    {
        return -1;
    }

    if ( read_complete ( random->fd, buf, len ) < 0 )
    {
        return -1;
    }

    return 0;
}

/**
 * Uninitialize random generator wrapper
 */
static void sc_random_free ( struct sc_random_t *random )
{
    if ( random->initialized )
    {
        close ( random->fd );
        random->initialized = FALSE;
    }
}

/**
 * Initialize SC context
 */
int sc_init ( struct sc_context_t *context, const uint8_t * key, size_t keylen )
{
    memset ( context, '\0', sizeof ( struct sc_context_t ) );

    context->initialized = FALSE;

    if ( keylen != sizeof ( context->aeskey ) )
    {
        return -1;
    }

    memcpy ( context->aeskey, key, keylen );

    if ( sc_random_init ( &context->random ) < 0 )
    {
        return -1;
    }

    context->initialized = TRUE;
    return 0;
}

/**
 * Uninitialize SC context
 */
void sc_free ( struct sc_context_t *context )
{
    if ( context->initialized )
    {
        sc_random_free ( &context->random );
        memset ( context, '\0', sizeof ( struct sc_context_t ) );
    }
}

/**
 * Create new SC stream
 */
int sc_new_stream ( struct sc_stream_t *stream, struct sc_context_t *context, int encrypt )
{
    uint8_t rawkey[AES256_KEYLEN];

    if ( encrypt < 0 )
    {
        stream->flags = SC_STREAM_INITIALIZED | SC_STREAM_BRIDGE_MODE;
        return 0;
    }

    memset ( stream, '\0', sizeof ( struct sc_stream_t ) );

    mbedtls_aes_init ( &stream->aes );

    if ( encrypt )
    {
        if ( sc_random_bytes ( &context->random, stream->iv, sizeof ( stream->iv ) ) < 0 )
        {
            return -1;
        }
    }

    memcpy ( rawkey, context->aeskey, AES256_KEYLEN );

    if ( encrypt )
    {
        if ( mbedtls_aes_setkey_enc ( &stream->aes, context->aeskey, AES256_KEYLEN_BITS ) != 0 )
        {
            mbedtls_aes_free ( &stream->aes );
            memset ( rawkey, '\0', sizeof ( rawkey ) );
            return -1;
        }

    } else
    {
        if ( mbedtls_aes_setkey_dec ( &stream->aes, context->aeskey, AES256_KEYLEN_BITS ) != 0 )
        {
            mbedtls_aes_free ( &stream->aes );
            memset ( rawkey, '\0', sizeof ( rawkey ) );
            return -1;
        }
    }

    memset ( rawkey, '\0', sizeof ( rawkey ) );

    stream->processed_size = 2 * AES256_BLOCKLEN + FORWARD_CHUNK_LEN;   /* iv + len + data */

    if ( !( stream->processed = ( uint8_t * ) malloc ( stream->processed_size ) ) )
    {
        mbedtls_aes_free ( &stream->aes );
        return -1;
    }

    stream->flags = SC_STREAM_INITIALIZED;

    if ( encrypt )
    {
        stream->flags |= SC_STREAM_ENCRYPT_MODE;
    }

    return 0;
}

/**
 * Encrypt traffic data
 */
static int sc_encrypt_data ( struct sc_stream_t *stream, const uint8_t * src, int len )
{
    int vlen;
    int ipos = 0;
    int opos = 0;
    uint8_t workbuf[AES256_BLOCKLEN];

    if ( len + 2 * AES256_BLOCKLEN > stream->processed_size
        || len >= 65536 || stream->processed_len )
    {
        return -1;
    }

    if ( ~stream->flags & SC_STREAM_SENT_TXNONCE )
    {
        memcpy ( stream->processed, stream->iv, AES256_BLOCKLEN );
        opos += AES256_BLOCKLEN;
        stream->flags |= SC_STREAM_SENT_TXNONCE;
    }

    workbuf[0] = ( len & 0xff00 ) >> 8;
    workbuf[1] = len & 0xff;

    vlen = len > AES256_BLOCKLEN - 2 ? AES256_BLOCKLEN - 2 : len;
    memset ( workbuf + 2, '\0', AES256_BLOCKLEN - 2 );
    memcpy ( workbuf + 2, src + ipos, vlen );
    ipos += vlen;

    if ( mbedtls_aes_crypt_cbc ( &stream->aes, MBEDTLS_AES_ENCRYPT, AES256_BLOCKLEN, stream->iv,
            workbuf, stream->processed + opos ) != 0 )
    {
        return -1;
    }

    opos += AES256_BLOCKLEN;

    while ( ipos < len )
    {
        if ( ( vlen = len - ipos ) > AES256_BLOCKLEN )
        {
            vlen = AES256_BLOCKLEN;
        }

        memset ( workbuf, '\0', AES256_BLOCKLEN );
        memcpy ( workbuf, src + ipos, vlen );
        ipos += vlen;

        if ( mbedtls_aes_crypt_cbc ( &stream->aes, MBEDTLS_AES_ENCRYPT, AES256_BLOCKLEN, stream->iv,
                workbuf, stream->processed + opos ) != 0 )
        {
            return -1;
        }

        opos += AES256_BLOCKLEN;
    }

    stream->processed_len = opos;

    return 0;
}

/**
 * Decrypt traffic data
 */
static int sc_decrypt_data ( struct sc_stream_t *stream, const uint8_t * src, int len )
{
    int vlen;
    int ipos = 0;
    int opos = 0;
    uint8_t workbuf[AES256_BLOCKLEN];

    if ( len >= stream->processed_size || stream->processed_len )
    {
        puts ( "ERRRR--2" );
        exit ( 2 );
        return -1;
    }

    if ( stream->unconsumed_len + len < AES256_BLOCKLEN )
    {
        memcpy ( stream->unconsumed + stream->unconsumed_len, src, len );
        stream->unconsumed_len += len;
        return 0;
    }

    vlen = AES256_BLOCKLEN - stream->unconsumed_len;
    memcpy ( stream->unconsumed + stream->unconsumed_len, src + ipos, vlen );
    ipos += vlen;
    stream->unconsumed_len = 0;

    if ( ~stream->flags & SC_STREAM_RECV_RXNONCE )
    {
        memcpy ( stream->iv, stream->unconsumed, AES256_BLOCKLEN );
        stream->flags |= SC_STREAM_RECV_RXNONCE;

    } else
    {
        if ( mbedtls_aes_crypt_cbc ( &stream->aes, MBEDTLS_AES_DECRYPT, AES256_BLOCKLEN, stream->iv,
                stream->unconsumed, workbuf ) != 0 )
        {
            return -1;
        }

        if ( stream->expected_len )
        {
            vlen = stream->expected_len > AES256_BLOCKLEN ? AES256_BLOCKLEN : stream->expected_len;
            memcpy ( stream->processed + opos, workbuf, vlen );
            opos += vlen;
            stream->expected_len -= vlen;

        } else
        {
            stream->expected_len = ( workbuf[0] << 8 ) | workbuf[1];
            vlen =
                stream->expected_len >
                AES256_BLOCKLEN - 2 ? AES256_BLOCKLEN - 2 : stream->expected_len;
            memcpy ( stream->processed + opos, workbuf + 2, vlen );
            opos += vlen;
            stream->expected_len -= vlen;
        }
    }

    while ( ipos + AES256_BLOCKLEN <= len )
    {
        if ( mbedtls_aes_crypt_cbc ( &stream->aes, MBEDTLS_AES_DECRYPT, AES256_BLOCKLEN, stream->iv,
                src + ipos, workbuf ) != 0 )
        {
            return -1;
        }

        ipos += AES256_BLOCKLEN;

        if ( stream->expected_len )
        {
            vlen = stream->expected_len > AES256_BLOCKLEN ? AES256_BLOCKLEN : stream->expected_len;
            memcpy ( stream->processed + opos, workbuf, vlen );
            opos += vlen;
            stream->expected_len -= vlen;

        } else
        {
            stream->expected_len = ( workbuf[0] << 8 ) | workbuf[1];
            vlen =
                stream->expected_len >
                AES256_BLOCKLEN - 2 ? AES256_BLOCKLEN - 2 : stream->expected_len;
            memcpy ( stream->processed + opos, workbuf + 2, vlen );
            opos += vlen;
            stream->expected_len -= vlen;
        }
    }

    stream->processed_len = opos;

    if ( ipos < len )
    {
        stream->unconsumed_len = len - ipos;
        memcpy ( stream->unconsumed, src + ipos, stream->unconsumed_len );
    }

    return 0;
}

/**
 * Process traffic data
 */
int sc_process_data ( struct sc_stream_t *stream, const uint8_t * src, int len )
{
    if ( ~stream->flags & SC_STREAM_INITIALIZED || stream->flags & SC_STREAM_ERROR_STATE )
    {
        return -1;
    }

    if ( stream->flags & SC_STREAM_BRIDGE_MODE )
    {
        memcpy ( stream->processed, src, len );
        stream->processed_len = len;
        return 0;
    }

    if ( stream->flags & SC_STREAM_ENCRYPT_MODE )
    {
        return sc_encrypt_data ( stream, src, len );
    }

    return sc_decrypt_data ( stream, src, len );
}

/**
 * Uninitialize SC stream
 */
void sc_free_stream ( struct sc_stream_t *stream )
{
    if ( stream->flags & SC_STREAM_INITIALIZED )
    {
        mbedtls_aes_free ( &stream->aes );
        memset ( stream->unconsumed, '\0', sizeof ( stream->unconsumed ) );
        memset ( stream->processed, '\0', stream->processed_size );
        free ( stream->processed );
        stream->flags = 0;
    }
}
