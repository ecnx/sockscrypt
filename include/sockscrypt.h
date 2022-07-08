/* ------------------------------------------------------------------
 * SocksCrypt - Proxy Task Header File
 * ------------------------------------------------------------------ */

#ifndef SOCKSCRYPT_H
#define SOCKSCRYPT_H

#include "defs.h"
#include "config.h"
#include "crypto.h"

#define L_ACCEPT                    0

#define LEVEL_AWAITING              1

/**
 * Utility data queue
 */
struct queue_t
{
    size_t len;
    uint8_t arr[DATA_QUEUE_CAPACITY];
};

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
    struct queue_t queue;

    struct sc_stream_t sc;
};

/**
 * Proxy program params
 */
struct proxy_t
{
    size_t stream_size;
    int verbose;
    int epoll_fd;
    struct stream_t *stream_head;
    struct stream_t *stream_tail;
    struct stream_t stream_pool[POOL_SIZE];

    int client_side_mode;

    struct sockaddr_storage entrance;
    struct sockaddr_storage endpoint;

    struct sc_context_t sc_context;
};

/**
 * Proxy task entry point
 */
extern int proxy_task ( struct proxy_t *params );

#include "util.h"

#endif
