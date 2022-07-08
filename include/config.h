/* ------------------------------------------------------------------
 * SocksCrypt - Project Config Header
 * ------------------------------------------------------------------ */

#ifndef SOCKSCRYPT_CONFIG_H
#define SOCKSCRYPT_CONFIG_H

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

#define SOCKSCRYPT_VERSION          "1.05.1a"
#define PROGRAM_SHORTCUT            "skcr"
#define POOL_SIZE                   256
#define LISTEN_BACKLOG              4
#define POLL_TIMEOUT_MSEC           16000
#define FORWARD_CHUNK_LEN           16384
#define DATA_QUEUE_CAPACITY         0

#ifndef SOCKSCRYPT_PRESET_KEY
#define SOCKSCRYPT_PRESET_KEY { 0 }
#endif

#endif
