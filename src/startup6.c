/* ------------------------------------------------------------------
 * SocksCrypt - Main Program File
 * ------------------------------------------------------------------ */

#include "proxy6.h"

/**
 * Show program usage message
 */
static void show_usage ( void )
{
    V ( printf
        ( "[socr] usage: sockscrypt6 [-cs] aeskey-file listen-addr-v6:listen-port endp-addr-v6:endp-port\n\n"
            "options:\n" "       -c                Client-side mode\n"
            "       -b                Bridge-side mode\n"
            "       -s                Server-side mode\n\n" "values:\n"
            "       aeskey-file       Plain AES-256 key file\n"
            "       listen-addr       Gateway address\n" "       listen-port       Gateway port\n"
            "       endp-addr         Endpoint address\n"
            "       endp-port         Endpoint port\n\n" ) );
}

/**
 * Decode ip address and port number
 */
static int ip_port_decode ( const char *input, struct in6_addr* addr, unsigned short *port )
{
    unsigned int lport;
    size_t len;
    const char *ptr, *ptr2;
    char buffer[INET6_ADDRSTRLEN];

    /* Find port number separator */
    if ( !( ptr = strrchr ( input, ':' ) ) )
    {
        return -1;
    }
    /* Validate destination buffer size */
    if ( ( len = ptr - input ) >= sizeof ( buffer ) )
    {
        return -1;
    }
    /* Save address string */
    memcpy ( buffer, input, len );
    buffer[len] = '\0';
    if ( !( ptr2 = strchr ( buffer, ':' ) ) )
    {
        memcpy ( buffer+7, input, len );
        buffer[len + 7] = '\0';
        memcpy ( buffer, "::FFFF:", 7 );
    }
    /* Parse IP address */
    if ( inet_pton ( AF_INET6, buffer, addr ) <= 0 )
    {
        return -1;
    }
    ptr++;

    /* Parse port b number */
    if ( sscanf ( ptr, "%u", &lport ) <= 0 || lport > 65535 )
    {
        return -1;
    }

    *port = lport;
    return 0;
}

/**
 * Program entry point
 */
int main ( int argc, char *argv[] )
{
    int fd;
    size_t len;
    struct proxy_t proxy;
    uint8_t key[AES256_KEYLEN];

    /* Show program version */
    V ( printf ( "[socr] SocksCrypt - ver. " SOCKSCRYPT_VERSION "\n" ) );

    /* Validate arguments count */
    if ( argc != 5 )
    {
        show_usage (  );
        return 1;
    }

    memset ( &proxy, '\0', sizeof ( proxy ) );

    if ( !strcmp ( argv[1], "-c" ) )
    {
        proxy.client_side_mode = 1;

    } else if ( !strcmp ( argv[1], "-b" ) )
    {
        proxy.client_side_mode = -1;

    } else if ( !strcmp ( argv[1], "-s" ) )
    {
        proxy.client_side_mode = 0;

    } else
    {
        show_usage (  );
        return 1;
    }

    if ( ip_port_decode ( argv[3], &proxy.listen_addr, &proxy.listen_port ) < 0 )
    {
        show_usage (  );
        return 1;
    }

    if ( ip_port_decode ( argv[4], &proxy.endpoint_addr, &proxy.endpoint_port ) < 0 )
    {
        show_usage (  );
        return 1;
    }

    if ( ( fd = open ( argv[2], O_RDONLY ) ) < 0 )
    {
        V ( fprintf ( stderr, "[socr] unable to open aes key file: %i\n", errno ) );
        return 1;
    }

    if ( ( ssize_t ) ( len = read ( fd, key, sizeof ( key ) ) ) < 0 )
    {
        V ( fprintf ( stderr, "[socr] unable to read aes key file: %i\n", errno ) );
        memset ( key, '\0', sizeof ( key ) );
        close ( fd );
        return 1;
    }

    close ( fd );

    if ( len < sizeof ( key ) )
    {
        V ( fprintf ( stderr, "[socr] aes key must be 32 bytes long.\n" ) );
        memset ( key, '\0', sizeof ( key ) );
        return 1;
    }

    if ( sc_init ( &proxy.sc_context, key, sizeof ( key ) ) < 0 )
    {
        V ( printf ( "[socr] crypto setup failed.\n" ) );
        return -1;
    }

    memset ( key, '\0', sizeof ( key ) );

    V ( printf ( "[socr] loaded password from file.\n" ) );

#if !defined(VERBOSE_MODE) && !defined(NO_DAEMON)

    V ( printf ( "[socr] switching to background mode...\n" ) );

    if ( daemon ( 0, 0 ) < 0 )
    {
        return -1;
    }
#endif

    for ( ;; )
    {
        if ( proxy_task ( &proxy ) < 0 )
        {
            if ( errno == EINTR || errno == ENOTCONN )
            {
                V ( printf ( "[socr] retrying in 1 sec...\n" ) );
                sleep ( 1 );

            } else
            {
                V ( printf ( "[socr] exit status: %i\n", errno ) );
                return 1;
            }
        }
    }

    sc_free ( &proxy.sc_context );

    V ( printf ( "[socr] exit status: success\n" ) );
    return 0;
}
