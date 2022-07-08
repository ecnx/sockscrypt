/* ------------------------------------------------------------------
 * SocksCrypt - Main Program File
 * ------------------------------------------------------------------ */

#include "sockscrypt.h"

/**
 * Show program usage message
 */
static void show_usage ( void )
{
    failure
        ( "usage: sockscrypt [-vdcs] aeskey-file listen-addr:listen-port endp-addr:endp-port\n\n"
        "       option -v         Enable verbose logging\n"
        "       option -d         Run in background\n" "       option -c         Client-side mode\n"
        "       option -s         Server-side mode\n"
        "       aeskey-file       Plain AES-256 key file\n"
        "       listen-addr       Gateway address\n" "       listen-port       Gateway port\n"
        "       endp-addr         Endpoint address\n"
        "       endp-port         Endpoint port\n\n" "Note: Both IPv4 and IPv6 can be used\n\n" );
}

/**
 * Program entry point
 */
int main ( int argc, char *argv[] )
{
    int fd;
    int daemon_flag = 0;
    size_t len;
    struct proxy_t proxy = { 0 };
    uint8_t key[AES256_KEYLEN];

    setbuf ( stdout, NULL );

    /* Show program version */
    info ( "SocksCrypt - ver. " SOCKSCRYPT_VERSION "\n" );

    /* Validate arguments count */
    if ( argc != 5 )
    {
        show_usage (  );
        return 1;
    }

    /* Work modes are all exclusice */
    if ( !!strchr ( argv[1], 'c' ) + !!strchr ( argv[1], 's' ) != 1 )
    {
        show_usage (  );
        return 1;
    }

    if ( strchr ( argv[1], 'c' ) )
    {
        proxy.client_side_mode = 1;

    } else if ( strchr ( argv[1], 's' ) )
    {
        proxy.client_side_mode = 0;

    } else
    {
        show_usage (  );
        return 1;
    }

    proxy.verbose = !!strchr ( argv[1], 'v' );
    daemon_flag = !!strchr ( argv[1], 'd' );

    if ( ip_port_decode ( argv[3], &proxy.entrance ) < 0 )
    {
        show_usage (  );
        return 1;
    }

    if ( ip_port_decode ( argv[4], &proxy.endpoint ) < 0 )
    {
        show_usage (  );
        return 1;
    }

    if ( ( fd = open ( argv[2], O_RDONLY ) ) < 0 )
    {
        failure ( "unable to open aes key file: %i\n", errno );
        return 1;
    }

    if ( ( ssize_t ) ( len = read ( fd, key, sizeof ( key ) ) ) < 0 )
    {
        failure ( "unable to read aes key file: %i\n", errno );
        memset ( key, '\0', sizeof ( key ) );
        close ( fd );
        return 1;
    }

    close ( fd );

    if ( len < sizeof ( key ) )
    {
        failure ( "aes key must be 32 bytes long\n" );
        memset ( key, '\0', sizeof ( key ) );
        return 1;
    }

    if ( sc_init ( &proxy.sc_context, key, sizeof ( key ) ) < 0 )
    {
        failure ( "crypto setup failed\n" );
        return -1;
    }

    memset ( key, '\0', sizeof ( key ) );

    info ( "loaded password from file\n" );

    /* Run in background if needed */
    if ( daemon_flag )
    {
        if ( daemon ( 0, 0 ) < 0 )
        {
            failure ( "cannot run in background: %i\n", errno );
            return 1;
        }
    }

    /* Launch the proxy task */
    if ( proxy_task ( &proxy ) < 0 )
    {
        failure ( "exit status: %i\n", errno );
        return 1;
    }

    info ( "exit status: success\n" );
    return 0;
}
