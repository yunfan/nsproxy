#pragma once

#ifndef __GNUC__
#error "Only support GNU C compiler"
#endif

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define container_of(ptr, type, member)                    \
    __extension__ ({                                       \
        const typeof(((type *)0)->member) *mptr__ = (ptr); \
        (type *)((char *)mptr__ - offsetof(type, member)); \
    })

#define arraysizeof(array) (sizeof(array) / sizeof(*(array)))

#define membersizeof(type, member) (sizeof(((type *)0)->member))

#define loglv(lv, str, ...)                                        \
    do {                                                           \
        if (nsproxy_verbose_level__ >= lv)                         \
            fprintf(stderr, "[nsproxy] " str "\n", ##__VA_ARGS__); \
    } while (0)

#define loginfo(str, ...) loglv(3, str, ##__VA_ARGS__)
#define logwarn(str, ...) loglv(3, "[WARN] " str, ##__VA_ARGS__)

/* Memory footprint of nsproxy is small, allocation failure are not expected
   and implies entire program is totally broken.
   Attempting to recover from such state is pointless.
*/
#define oom()                                                              \
    do {                                                                   \
        /* Check return value to make GCC happy. Don't use stdio in oom */ \
        if (write(STDERR_FILENO, "Out of Memory\n", 14)) {}                \
        abort();                                                           \
    } while (0)

#define current_nspconf() (nsproxy_current_nspconf__)

#ifndef static_assert
#if defined(__GNUC__) && (__GNUC__ > 4)
#define static_assert(cond, msg) __extension__ _Static_assert(cond, msg)
#else
#define static_assert(cond, msg)
#endif
#endif

enum {
    DNS_REDIR_OFF,
    DNS_REDIR_TCP,
    DNS_REDIR_UDP
};

enum {
    PROXY_SOCKS5,
    PROXY_HTTP,
    PROXY_DIRECT
};

/* rfc1035(domain name): the total length of a domain name is restricted to 255
   octets or less */
#define SERVNAME_MAXLEN 255

/* rfc1929(socks5 auth): length of UNAME / PASSWD could be 1-255 */
#define AUTH_MAXLEN 255

/* rfc768(UDP) */
#define UDP_PACKET_MAXLEN 65535

struct nspconf {
    char proxysrv[SERVNAME_MAXLEN + 1];
    uint16_t proxyport;
    uint8_t proxytype;
    char dnssrv[SERVNAME_MAXLEN + 1];
    uint16_t dnsport;
    uint8_t dnstype;
    char proxyuser[AUTH_MAXLEN + 1];   /* Proxy username for authentication */
    char proxypass[AUTH_MAXLEN + 1];   /* Proxy password for authentication */
    uint8_t ipv6;
};

extern int nsproxy_verbose_level__;
extern struct nspconf *nsproxy_current_nspconf__;
