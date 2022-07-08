/* ------------------------------------------------------------------
 * SocksCrypt - Proxy Task Source Code
 * ------------------------------------------------------------------ */

#include "sockscrypt.h"

/**
 * Estabilish connection with endpoint
 */
static int setup_endpoint_stream ( struct proxy_t *proxy, struct stream_t *stream,
    struct sockaddr_storage *saddr )
{
    int sock;
    struct stream_t *neighbour;

    /* Connect remote endpoint asynchronously */
    if ( ( sock = connect_async ( proxy, saddr ) ) < 0 )
    {
        return sock;
    }

    /* Try allocating neighbour stream */
    if ( !( neighbour = insert_stream ( proxy, sock ) ) )
    {
        force_cleanup ( proxy, stream );
        neighbour = insert_stream ( proxy, sock );
    }

    /* Check for neighbour stream */
    if ( !neighbour )
    {
        shutdown_then_close ( proxy, sock );
        return -2;
    }

    /* Setup stream crypto context */
    if ( sc_new_stream ( &neighbour->sc, &proxy->sc_context, !proxy->client_side_mode ) < 0 )
    {
        remove_stream ( proxy, neighbour );
        shutdown_then_close ( proxy, sock );
        return -1;
    }

    /* Set neighbour role */
    neighbour->role = S_PORT_B;
    neighbour->level = LEVEL_CONNECTING;
    neighbour->events = POLLIN | POLLOUT;

    /* Build up a new relation */
    neighbour->neighbour = stream;
    stream->neighbour = neighbour;

    return 0;
}

/**
 * Handle new stream creation
 */
static int handle_new_stream ( struct proxy_t *proxy, struct stream_t *stream )
{
    int status;
    struct stream_t *util;

    if ( ~stream->revents & POLLIN )
    {
        return -1;
    }

    /* Accept incoming connection */
    if ( !( util = accept_new_stream ( proxy, stream->fd ) ) )
    {
        return -2;
    }

    /* Setup stream crypto context */
    if ( sc_new_stream ( &util->sc, &proxy->sc_context, proxy->client_side_mode ) < 0 )
    {
        remove_stream ( proxy, util );
        return -1;
    }

    /* Setup new stream */
    util->role = S_PORT_A;
    util->level = LEVEL_AWAITING;
    util->events = 0;

    /* Setup endpoint stream */
    if ( ( status = setup_endpoint_stream ( proxy, util, &proxy->endpoint ) ) < 0 )
    {
        remove_stream ( proxy, util );
        return status;
    }

    return 0;
}

/**
 * Handle stream binding
 */
static int handle_stream_binding ( struct stream_t *stream )
{
    if ( stream->level == LEVEL_CONNECTING && stream->revents & ( POLLIN | POLLOUT ) )
    {
        stream->level = LEVEL_FORWARDING;
        stream->events = POLLIN;
        stream->neighbour->level = LEVEL_FORWARDING;
        stream->neighbour->events = POLLIN;
        return 0;
    }

    return -1;
}

/**
 * Handle stream data forward
 */
static int sc_handle_forward_data ( struct proxy_t *proxy, struct stream_t *stream )
{
    int len = FORWARD_CHUNK_LEN;
    int sendlim;
    int sendwip;
    socklen_t optlen;
    uint8_t buffer[2 * AES256_BLOCKLEN + FORWARD_CHUNK_LEN];

    if ( !stream->neighbour || stream->level != LEVEL_FORWARDING )
    {
        return -1;
    }

    if ( stream->revents & POLLOUT )
    {
        if ( !stream->neighbour->sc.processed_len )
        {
            stream->events &= ~POLLOUT;
            stream->neighbour->events |= POLLIN;
            return 0;
        }

        if ( ioctl ( stream->fd, TIOCOUTQ, &sendwip ) < 0 )
        {
            failure ( "cannot get socket:%i pending bytes count (%i)\n", stream->neighbour->fd,
                errno );
            return -1;
        }

        optlen = sizeof ( sendlim );

        if ( getsockopt ( stream->fd, SOL_SOCKET, SO_SNDBUF, &sendlim, &optlen ) < 0 )
        {
            failure ( "cannot get socket:%i output capacity (%i)\n", stream->neighbour->fd, errno );
            return -1;
        }

        if ( optlen != sizeof ( sendlim ) )
        {
            failure ( "socket:%i output capacity data type is invalid\n", stream->neighbour->fd );
            return -1;
        }

        if ( sendwip > sendlim )
        {
            failure ( "socket:%i capacity is less than data pending\n", stream->neighbour->fd );
            return -1;
        }

        sendlim -= sendwip;

        if ( !sendlim )
        {
            failure ( "socket:%i was expected to be write ready\n", stream->neighbour->fd );
            return -1;
        }

        if ( sendlim < len )
        {
            len = sendlim;
            verbose ( "bytes count limited to socket:%i output capacity: %i\n",
                stream->neighbour->fd, len );
        }

        if ( stream->neighbour->sc.processed_len < len )
        {
            len = stream->neighbour->sc.processed_len;
            verbose ( "bytes count limited to socket:%i processed data length: %i\n",
                stream->neighbour->fd, len );
        }

        if ( ( len = send ( stream->fd, stream->neighbour->sc.processed, len, MSG_NOSIGNAL ) ) < 0 )
        {
            failure ( "cannot send data to socket:%i\n", stream->neighbour->fd );
            return -1;
        }

        stream->neighbour->sc.processed_len -= len;

        verbose ( "bytes sent to socket:%i count %i left %i\n", stream->neighbour->fd, len,
            stream->neighbour->sc.processed_len );

        if ( stream->neighbour->sc.processed_len )
        {
            memcpy ( buffer, stream->neighbour->sc.processed + len,
                stream->neighbour->sc.processed_len );
            memcpy ( stream->neighbour->sc.processed, buffer, stream->neighbour->sc.processed_len );

        } else
        {
            stream->events &= ~POLLOUT;
            stream->neighbour->events |= POLLIN;
        }

    } else if ( stream->revents & POLLIN )
    {
        if ( ( len = recv ( stream->fd, buffer, FORWARD_CHUNK_LEN, 0 ) ) <= 0 )
        {
            failure ( "cannot receive data (%i) from socket:%i\n", errno, stream->fd );
            return -1;
        }

        if ( sc_process_data ( &stream->sc, buffer, len ) < 0 )
        {
            failure ( "crypto data processing failed between socket:%i and socket:%i\n", stream->fd,
                stream->neighbour->fd );
            return -1;
        }

        stream->events &= ~POLLIN;
        stream->neighbour->events |= POLLOUT;
    }

    return 0;
}

/**
 * Handle stream events
 */
int handle_stream_events ( struct proxy_t *proxy, struct stream_t *stream )
{
    int status;

    if ( sc_handle_forward_data ( proxy, stream ) >= 0 )
    {
        return 0;
    }

    switch ( stream->role )
    {
    case L_ACCEPT:
        show_stats ( proxy );
        if ( handle_new_stream ( proxy, stream ) == -2 )
        {
            return -1;
        }
        return 0;
    case S_PORT_B:
        if ( ( status = handle_stream_binding ( stream ) ) >= 0 )
        {
            return 0;
        }
        break;
    }

    remove_relation ( stream );

    return 0;
}

/**
 * Proxy task entry point
 */
int proxy_task ( struct proxy_t *proxy )
{
    int status = 0;
    int sock;
    struct stream_t *stream;

    /* Set stream size */
    proxy->stream_size = sizeof ( struct stream_t );

    /* Reset current state */
    proxy->stream_head = NULL;
    proxy->stream_tail = NULL;
    memset ( proxy->stream_pool, '\0', sizeof ( proxy->stream_pool ) );

    /* Proxy events setup */
    if ( proxy_events_setup ( proxy ) < 0 )
    {
        return -1;
    }

    /* Setup listen socket */
    if ( ( sock = listen_socket ( proxy, &proxy->entrance ) ) < 0 )
    {
        if ( proxy->epoll_fd >= 0 )
        {
            close ( proxy->epoll_fd );
        }
        return -1;
    }

    /* Allocate new stream */
    if ( !( stream = insert_stream ( proxy, sock ) ) )
    {
        shutdown_then_close ( proxy, sock );
        if ( proxy->epoll_fd >= 0 )
        {
            close ( proxy->epoll_fd );
        }
        return -1;
    }

    /* Update listen stream */
    stream->role = L_ACCEPT;
    stream->events = POLLIN;

    verbose ( "proxy setup was successful\n" );

    /* Run forward loop */
    while ( ( status = handle_streams_cycle ( proxy ) ) >= 0 );

    /* Do not close reset pipe */
    stream->fd = -1;

    /* Remove all streams */
    remove_all_streams ( proxy );

    /* Close epoll fd if created */
    if ( proxy->epoll_fd >= 0 )
    {
        close ( proxy->epoll_fd );
        proxy->epoll_fd = -1;
    }

    verbose ( "done proxy uninitializing\n" );

    return status;
}
