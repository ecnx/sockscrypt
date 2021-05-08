/* ------------------------------------------------------------------
 * SocksCrypt - Proxy Task Header File
 * ------------------------------------------------------------------ */

#ifndef PROXY_H
#define PROXY_H

#include "config.h"
#include "crypto.h"

#define S_INVALID                   -1
#define L_ACCEPT                    0
#define S_PORT_A                    1
#define S_PORT_B                    2

#define LEVEL_NONE                  0
#define LEVEL_AWAITING              1
#define LEVEL_CONNECTING            2
#define LEVEL_FORWARDING            3

#define EPOLLREF                    ((struct pollfd*) -1)

/**
 * IP/TCP connection stream
 */
struct stream_t
{
    int role;
    int fd;
    int level;
    int allocated;
    int abandoned;
    short events;
    short levents;
    short revents;

    struct pollfd *pollref;
    struct stream_t *neighbour;
    struct stream_t *prev;
    struct stream_t *next;

    struct sc_stream_t sc;
};

/**
 * Proxy program params
 */
struct proxy_t
{
    int client_side_mode;
    struct sc_context_t sc_context;
    int epoll_fd;
    unsigned int listen_addr;
    unsigned short listen_port;

    unsigned int endpoint_addr;
    unsigned short endpoint_port;

    struct stream_t *stream_head;
    struct stream_t *stream_tail;
    struct stream_t stream_pool[POOL_SIZE];
};

/**
 * Proxy task entry point
 */
extern int proxy_task ( struct proxy_t *params );

#endif
