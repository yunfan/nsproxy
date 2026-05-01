#pragma once
#include <stddef.h>
#include <sys/socket.h>
#include "loop.h"

struct buff {
    size_t capacity;
    size_t size;
    char data[];
};

#define buff_calloc(n) __extension__ ({                         \
    size_t n__ = (n);                                           \
    struct buff *buff__ = calloc(1, sizeof(struct buff) + n__); \
    if (buff__ != NULL) buff__->capacity = n__;                 \
    buff__;                                                     \
})

struct skinfo {
    /* for stat */
    size_t nsent;
    size_t nread;
    /* for display only */
    const char *proto;
    const char *addr;
    uint16_t port;
};

/* Create socket fd and connect to addr:port, with log prints
   return socked fd if succeed, otherwise -errno */
int skutils_connect(struct skinfo *info, const char *addr, uint16_t port,
                    int type);

/* events control
   'mask' and '*events' is same as epoll_ctl(2)
   'enable' indicate bits contain in event should be set or unset
   will read and update *events, if *events is changed, update listening epoll
   events of 'sfd' in 'loop' and update callback to 'epcb'
   return 0 if succeed, otherwise -errno
*/
int skutils_evctl(struct loopctx *loop, int sfd, unsigned int *events,
                  struct epcb_ops *epcb, unsigned int mask, int enable);

/* send(2), with log prints
   return number of bytes sent, otherwise -errno on error */
ssize_t skutils_send(struct skinfo *info, int sfd, const char *data,
                     size_t size);

/* sendmsg(2), with log prints
   return number of bytes sent, otherwise -errno on error */
ssize_t skutils_sendmsg(struct skinfo *info, int sfd, struct msghdr *msg);

/* recv(2), with log prints
   return number of bytes received, otherwise -errno on error */
ssize_t skutils_recv(struct skinfo *info, int sfd, char *data, size_t size);

/* shutdown(2), with log prints
   if rst is set, connection will be forcefully close, and *sfd set to -1 */
int skutils_shutdown(struct skinfo *info, struct loopctx *loop, int *sfd,
                     int how, int rst);

/* epoll_ctl(DEL) then close(), with log print
   also set *sfd to -1
*/
void skutils_close_unreg(struct skinfo *info, struct loopctx *loop, int *sfd);
