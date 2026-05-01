#include "socks.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "loop.h"
#include "skutils.h"

#define SOCKS_HS_BUFF 1024

/* socks handshake phases */
enum {
    PHASE_SEND_METHOD = 1,
    PHASE_RECV_METHOD,
    PHASE_SEND_AUTH,
    PHASE_RECV_AUTH,
    PHASE_SEND_REQUEST,
    PHASE_RECV_REPLY,
    PHASE_FORWARDING,
};

static const char *phasestr[] = {
    [PHASE_SEND_METHOD] = "PHASE_SEND_METHOD",
    [PHASE_RECV_METHOD] = "PHASE_RECV_METHOD",
    [PHASE_SEND_AUTH] = "PHASE_SEND_AUTH",
    [PHASE_RECV_AUTH] = "PHASE_RECV_AUTH",
    [PHASE_SEND_REQUEST] = "PHASE_SEND_REQUEST",
    [PHASE_RECV_REPLY] = "PHASE_RECV_REPLY",
    [PHASE_FORWARDING] = "PHASE_FORWARDING",
};

static const char *rspstr[] = {
    [0] = "Succeeded",
    [1] = "General SOCKS server failure",
    [2] = "Connection not allowed by ruleset",
    [3] = "Network unreachable",
    [4] = "Host unreachable",
    [5] = "Connection refused",
    [6] = "TTL expired",
    [7] = "Command not supported",
    [8] = "Address type not supported",
    [9] = "Unassigned",
};

/* - TCP_FORWARD: connected to proxy, for TCP only
 * - UDP_FORWARD: connected to relay server, for UDP foward only
 * - UDP_ASSOCIATE: connected to proxy, for UDP associate handshake only
 */
enum {
    TCP_FORWARD,
    UDP_FORWARD,
    UDP_ASSOCIATE,
};

struct reladdr {
    char addr[SERVNAME_MAXLEN + 1];
    uint16_t port;
};

struct proxy_socks {
    struct proxy ops;

    /* loop */
    struct loopctx *loop;
    struct epcb_ops epcb;

    /* socket */
    int sfd;
    unsigned int events;

    /* rc */
    int refcnt;

    /* user */
    userev_fn_t *userev;
    void *userp;

    /* target */
    char *addr;
    uint16_t port;

    /* info */
    struct skinfo info;

    /* handshake */
    int type; /* TCP_FORWARD / UDP_FORWARD / UDP_ASSOCIATE */
    int phase;
    struct buff *hsbuff;

    /* for udp forward only */
    struct reladdr *relay;
};

struct socks5hdr {
    uint8_t ver;
    union {
        uint8_t cmd; /* for request */
        uint8_t rsp; /* for reply */
    };
    union {
        uint8_t rsv;
        uint8_t frag /* for udp only */;
    };
};

/* not really message layout, just used as parameter type for util function */
struct socks5addr {
    char addr[256];
    uint16_t port;
};
#define SOCKS5_ATYPE_INET4  1
#define SOCKS5_ATYPE_DOMAIN 3
#define SOCKS5_ATYPE_INET6  4

#define SOCKS5_CMD_CONNECT  1
#define SOCKS5_CMD_UDPASSOC 3


/* put socks5 header to buffer,
   return the number of bytes written , or -1 if failed */
static ssize_t socks5_hdr_put(char *buffer, size_t size,
                              const struct socks5hdr *hdr)
{
    if (sizeof(struct socks5hdr) > size)
        return -1;
    memcpy(buffer, hdr, sizeof(struct socks5hdr));
    return sizeof(struct socks5hdr);
}

/* get socks5 header from buffer,
   return the number of bytes written, or -1 if failed */
static ssize_t socks5_hdr_get(struct socks5hdr *hdr, const char *buffer,
                              size_t size)
{
    if (sizeof(struct socks5hdr) > size)
        return -1;
    memcpy(hdr, buffer, sizeof(struct socks5hdr));
    return sizeof(struct socks5hdr);
}

/* put socks5 ATYPE, ADDR and PORT to buffer
   addr could be either domain or ipv4/6 address presented in string */
static ssize_t socks5_addr_put(char *buffer, size_t size,
                               const struct socks5addr *addr)
{
    size_t offset = 0;
    struct in_addr in4;
    struct in6_addr in6;
    uint8_t atype, alen;
    const void *aptr;
    uint16_t portbe = htobe16(addr->port);

    /* determine address type and length */
    if (inet_pton(AF_INET, addr->addr, &in4) == 1) {
        atype = SOCKS5_ATYPE_INET4;
        alen = sizeof(in4);
        aptr = &in4;
    } else if (inet_pton(AF_INET6, addr->addr, &in6) == 1) {
        atype = SOCKS5_ATYPE_INET6;
        alen = sizeof(in6);
        aptr = &in6;
    } else {
        atype = SOCKS5_ATYPE_DOMAIN;
        alen = strlen(addr->addr);
        aptr = addr->addr;
    }

    /* check buffer is big enough */
    if (atype == SOCKS5_ATYPE_DOMAIN) {
        if (sizeof(atype) + sizeof(alen) + alen + sizeof(portbe) > size)
            return -1;
    } else {
        if (sizeof(atype) + alen + sizeof(portbe) > size)
            return -1;
    }

    /* copy to buffer */
    memcpy(buffer + offset, &atype, sizeof(atype));
    offset += sizeof(atype);

    if (atype == SOCKS5_ATYPE_DOMAIN) {
        memcpy(buffer + offset, &alen, sizeof(alen));
        offset += sizeof(alen);
    }

    memcpy(buffer + offset, aptr, alen);
    offset += alen;

    memcpy(buffer + offset, &portbe, sizeof(portbe));
    offset += sizeof(portbe);

    return offset;
}

/* get socks5 address from buffer, buffer should pointing to ATYPE
   if ATYPE is ipv4/v6 address, this function will return string representation
 */
static ssize_t socks5_addr_get(struct socks5addr *addr, const char *buffer,
                               size_t size)
{
    const char *cur = buffer;
    struct in_addr in4;
    struct in6_addr in6;
    uint8_t atype, alen;
    uint16_t portbe;

    if (cur - buffer + sizeof(atype) > size)
        return -1;
    memcpy(&atype, cur, sizeof(atype));
    cur += sizeof(atype);

    switch (atype) {
    case SOCKS5_ATYPE_INET4:
        if (cur - buffer + sizeof(in4) > size)
            return -1;
        memcpy(&in4, cur, sizeof(in4));
        cur += sizeof(in4);

        inet_ntop(AF_INET, &in4, addr->addr, sizeof(addr->addr));
        break;

    case SOCKS5_ATYPE_INET6:
        if (cur - buffer + sizeof(in6) > size)
            return -1;
        memcpy(&in6, cur, sizeof(in6));
        cur += sizeof(in6);

        inet_ntop(AF_INET6, &in6, addr->addr, sizeof(addr->addr));
        break;

    case SOCKS5_ATYPE_DOMAIN:
        if (cur - buffer + sizeof(alen) > size)
            return -1;
        memcpy(&alen, cur, sizeof(alen));
        cur += sizeof(alen);

        if (cur - buffer + alen > (ssize_t)size)
            return -1;
        memset(addr->addr, 0, sizeof(addr->addr));
        memcpy(addr->addr, cur, alen);
        cur += alen;
        break;

    default:
        return -1;
    }

    if (cur - buffer + sizeof(portbe) > size)
        return -1;
    memcpy(&portbe, cur, sizeof(portbe));
    cur += sizeof(portbe);

    addr->port = be16toh(portbe);

    return cur - buffer;
}

static void socks_handshake_perror(struct proxy_socks *self, int err)
{
    if (err > 0)
        loglv(0, "Proxy server reset unexpectedly during SOCKS5 handshake "
                 "phase [%s]: %s", phasestr[self->phase], strerror(err));
    else
        loglv(0, "Proxy server closed unexpectedly during SOCKS5 handshake "
                 "phase [%s]", phasestr[self->phase]);
}

static void socks_handshake_output(struct proxy_socks *self)
{
    struct nspconf *conf = current_nspconf();
    ssize_t nsent;
    struct buff *buff = self->hsbuff;

    /* it's first called to this phase, assembly buffer */
    if (buff->size == 0) {
        if (self->phase == PHASE_SEND_METHOD) {
            buff->data[buff->size++] = 5; /* ver */
            if (conf->proxyuser[0] != '\0') {
                buff->data[buff->size++] = 2; /* num methods */
                buff->data[buff->size++] = 0; /* no auth */
                buff->data[buff->size++] = 2; /* user/pass auth */
            } else {
                buff->data[buff->size++] = 1; /* num methods */
                buff->data[buff->size++] = 0; /* no auth */
            }
        }
        if (self->phase == PHASE_SEND_AUTH) {
            size_t ulen = strlen(conf->proxyuser);
            size_t plen = strlen(conf->proxypass);

            buff->data[buff->size++] = 1; /* ver */
            buff->data[buff->size++] = (uint8_t)ulen;
            memcpy(buff->data + buff->size, conf->proxyuser, ulen);
            buff->size += ulen;
            buff->data[buff->size++] = (uint8_t)plen;
            memcpy(buff->data + buff->size, conf->proxypass, plen);
            buff->size += plen;
        }
        if (self->phase == PHASE_SEND_REQUEST) {
            struct socks5hdr hdr;
            struct socks5addr ad;
            ssize_t ret;

            hdr.ver = 0x5;
            hdr.cmd = self->type == TCP_FORWARD ? SOCKS5_CMD_CONNECT
                                                : SOCKS5_CMD_UDPASSOC;
            hdr.rsv = 0x0;

            snprintf(ad.addr, sizeof(ad.addr), "%s", self->addr);
            ad.port = self->port;

            ret = socks5_hdr_put(buff->data + buff->size,
                                 buff->capacity - buff->size, &hdr);
            if (ret == -1) {
                fprintf(stderr, "an invariant violation has been detected.\n");
                abort();
            }
            buff->size += ret;

            ret = socks5_addr_put(buff->data + buff->size,
                                  buff->capacity - buff->size, &ad);
            if (ret == -1) {
                fprintf(stderr, "an invariant violation has been detected.\n");
                abort();
            }
            buff->size += ret;
        }
    }

    nsent = send(self->sfd, buff->data, buff->size, MSG_NOSIGNAL);
    if (nsent == -1) {
        if (errno != EAGAIN) {
            socks_handshake_perror(self, errno);
            self->userev(self->userp, 0, -1);
        }
        return;
    }
    buff->size -= nsent;

    if (buff->size != 0) {
        /* partial write, wait next time to write rest */
        memmove(buff->data, buff->data + nsent, buff->size);
        return;
    }

    switch (self->phase) {
        case PHASE_SEND_METHOD:  self->phase = PHASE_RECV_METHOD; break;
        case PHASE_SEND_AUTH:    self->phase = PHASE_RECV_AUTH;   break;
        case PHASE_SEND_REQUEST: self->phase = PHASE_RECV_REPLY;  break;
    }

    loop_epoll_ctl(self->loop, EPOLL_CTL_MOD, self->sfd, EPOLLIN, &self->epcb);
}

static void socks_handshake_input(struct proxy_socks *self)
{
    ssize_t nread;
    struct buff *buff = self->hsbuff;

    if (self->phase == PHASE_RECV_METHOD) {
        nread = recv(self->sfd, buff->data + buff->size,
                     buff->capacity - buff->size, 0);
        if (nread <= 0) {
            if (nread == 0 || errno != EAGAIN) {
                socks_handshake_perror(self, nread == -1 ? errno : 0);
                self->userev(self->userp, 0, -1);
            }
            return;
        }
        buff->size += nread;

        /* wait more data */
        if (buff->size < 2)
            return;

        /* no a correct protocol header */
        if (buff->data[0] != 5) {
            loglv(0, "Proxy server retern a bad reply: VER field is 0x%02x, "
                     "expected 0x05", (unsigned char)buff->data[0]);
            self->userev(self->userp, 0, -1);
            return;
        }

        /* server reject our all method */
        if ((unsigned char)buff->data[1] == 0xFF) {
            loglv(0, "Proxy server requires authentication. "
                     "Please check your username and password.");
            self->userev(self->userp, 0, -1);
            return;
        } /* - else: server selected a method */

        /* should be only one method */
        if (buff->size != 2) {
            loglv(0, "Proxy server returned invalid method response");
            self->userev(self->userp, 0, -1);
            return;
        }

        /* see what method server selected */
        if (buff->data[1] == 2) {
            /* username password auth */
            self->phase = PHASE_SEND_AUTH;
        } else if (buff->data[1] == 0) {
            /* no auth */
            self->phase = PHASE_SEND_REQUEST;
        } else {
            /* other */
            loglv(0, "Proxy server returned unsupported authentication "
                     "method: 0x%02x", (unsigned char)buff->data[1]);
            self->userev(self->userp, 0, -1);
            return;
        }
    }

    if (self->phase == PHASE_RECV_AUTH) {
        nread = recv(self->sfd, buff->data + buff->size,
                     buff->capacity - buff->size, 0);
        if (nread <= 0) {
            if (nread == 0 || errno != EAGAIN) {
                socks_handshake_perror(self, nread == -1 ? errno : 0);
                self->userev(self->userp, 0, -1);
            }
            return;
        }
        buff->size += nread;

        /* hanshake failed because server didn't follow RFC1929 */
        if (buff->size > 2) {
            loglv(0, "Proxy server returned invalid auth response");
            self->userev(self->userp, 0, -1);
            return;
        }

        /* wait more data */
        if (buff->size != 2)
            return;

        if (buff->data[0] != 1 || buff->data[1] != 0) {
            loglv(0, "SOCKS5 authentication failed. "
                     "Please check your username and password.");
            self->userev(self->userp, 0, -1);
            return;
        }

        /* good, server replied correctly */
        self->phase = PHASE_SEND_REQUEST;
    }


    if (self->phase == PHASE_RECV_REPLY) {
        struct socks5hdr hdr = { 0 };
        struct socks5addr ad;
        ssize_t s;
        int pass; /* did handshake finished? */

        /* use MSG_PEEK here, if some application layer data has been returned,
           we can carefuly not to touch them */
        nread = recv(self->sfd, buff->data + buff->size,
                     buff->capacity - buff->size - 1, MSG_PEEK);
        if (nread <= 0) {
            if (nread == 0 || errno != EAGAIN) {
                socks_handshake_perror(self, nread == -1 ? errno : 0);
                self->userev(self->userp, 0, -1);
            }
            return;
        }

        /* determine whether handshake finished, and boundary of handshake
           message */
        do {
            ssize_t ret, offset = 0;

            s = nread;
            pass = 0;

            ret = socks5_hdr_get(&hdr, buff->data + offset,
                                buff->size + nread - offset);
            if (ret == -1)
                break;
            offset += ret;

            ret = socks5_addr_get(&ad, buff->data + offset,
                                buff->size + nread - offset);
            if (ret == -1)
                break;
            offset += ret;

            s = offset - buff->size;
            pass = 1;
        } while (0);

        /* discard socks handshake reply part in socket buffer */
        nread = recv(self->sfd, buff->data + buff->size, s, 0);
        if (nread != s) {
            fprintf(stderr, "recv() returned %zd, expected %zd\n", nread, s);
            abort();
        }
        buff->size += nread;

        /* handshake not finished */
        if (!pass) {
            /* failed, handshake not finished but connection lost or buffer
               full */
            if (buff->size == buff->capacity) {
                loglv(0, "Proxy server returned a header that is too large "
                         "during the handshake.");
                self->userev(self->userp, 0, -1);
            }

            /* if not failed, wait for rest handshake message */
            return;
        }

        if (hdr.ver != 5) {
            loglv(0, "Proxy server retern a bad reply: VER field is 0x%02x, "
                     "expected 0x05", hdr.ver);
            self->userev(self->userp, 0, -1);
            return;
        }

        if (hdr.rsp != 0) {
            if (hdr.rsp == 2) {
                loglv(0, "Proxy server rejected our request: %s. "
                         "Please check your username and password.",
                         rspstr[2]);
            } else {
                loglv(0, "Proxy server rejected our request: %s",
                         hdr.rsp > 9 ? rspstr[9] : rspstr[hdr.rsp]);
            }
            self->userev(self->userp, 0, -1);
            return;
        }

        if (self->type == UDP_ASSOCIATE) {
            loglv(1, "UDP relay address: %s:%u", ad.addr, (unsigned)ad.port);
            if ((self->relay = calloc(1, sizeof(struct reladdr))) == NULL)
                oom();
            static_assert(sizeof(self->relay->addr) >= sizeof(ad.addr),
                          "???");
            strcpy(self->relay->addr, ad.addr);
            self->relay->port = ad.port;
        }

        self->phase = PHASE_FORWARDING;
        loglv(2, "... handshaked %s:%u", self->addr, (unsigned)self->port);
    }

    /* clear input buffer */
    buff->size = 0;

    /* when control flow reach here, it should finish a step of input phase */
    if (self->phase == PHASE_SEND_REQUEST || self->phase == PHASE_SEND_AUTH) {
        loop_epoll_ctl(self->loop, EPOLL_CTL_MOD, self->sfd, EPOLLOUT,
                       &self->epcb);
    } else {
        assert(self->phase == PHASE_FORWARDING);
        self->events = EPOLLOUT | EPOLLIN;
        loop_epoll_ctl(self->loop, EPOLL_CTL_MOD, self->sfd, self->events,
                       &self->epcb);
        free(self->hsbuff);
        self->hsbuff = NULL;
    }
}

static void socks_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct proxy_socks *self = container_of(epcb, struct proxy_socks, epcb);

    /* we don't care events after handshaked, just forward event to user */
    if (self->phase == PHASE_FORWARDING) {
        self->userev(self->userp, events, 0);
        return;
    }

    loglv(3, "socks_epcb_events: handshaking with %s:%u/%s [%s]",
             self->addr, (unsigned)self->port,
             self->type == TCP_FORWARD ? "tcp" : "udp", phasestr[self->phase]);

    if (self->phase == PHASE_SEND_METHOD || self->phase == PHASE_SEND_AUTH ||
        self->phase == PHASE_SEND_REQUEST) {
        socks_handshake_output(self);
    } else {
        socks_handshake_input(self);
    }
}

/* impl for struct proxy :: shutdown */
static int socks_shutdown(struct proxy *proxy, int how, int rst)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);
    return self->phase != PHASE_FORWARDING
        ? -EAGAIN
        : skutils_shutdown(&self->info, self->loop, &self->sfd, how, rst);
}

/* impl for struct proxy :: evctl */
static int socks_evctl(struct proxy *proxy, unsigned int event, int enable)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);
    return self->phase != PHASE_FORWARDING
        ? -EAGAIN
        : skutils_evctl(self->loop, self->sfd, &self->events, &self->epcb,
                        event, enable); 
}

/* impl for struct proxy :: send */
static ssize_t socks_send(struct proxy *proxy, const char *data, size_t size)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);

    /* handshake is not finished */
    if (self->phase != PHASE_FORWARDING) {
        return -EAGAIN;
    }

    if (self->type == UDP_FORWARD) {
        char buffer[512]; /* for socks header only  */
        struct msghdr msg;
        struct iovec iov[2];
        size_t iovlen = 0;
        struct socks5hdr hdr = { 0 };
        struct socks5addr addr;
        size_t offset = 0;
        ssize_t ret;

        snprintf(addr.addr, sizeof(addr.addr), "%s", self->addr);
        addr.port = self->port;

        ret = socks5_hdr_put(buffer + offset, sizeof(buffer) - offset, &hdr);
        offset += ret;

        ret = socks5_addr_put(buffer + offset, sizeof(buffer) - offset, &addr);
        offset += ret;

        iov[iovlen].iov_base = buffer;
        iov[iovlen].iov_len = offset;
        iovlen++;
        iov[iovlen].iov_base = (void *)data;
        iov[iovlen].iov_len = size;
        iovlen++;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = iov;
        msg.msg_iovlen = iovlen;

        return skutils_sendmsg(&self->info, self->sfd, &msg);
    } else {
        return skutils_send(&self->info, self->sfd, data, size);
    }
}

/* impl for struct proxy :: recv */
static ssize_t socks_recv(struct proxy *proxy, char *data, size_t size)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);
    ssize_t nread;

    /* handshake is not finished */
    if (self->phase != PHASE_FORWARDING) {
        return -EAGAIN;
    }

    nread = skutils_recv(&self->info, self->sfd, data, size);
    if (nread < 0)
        return nread;

    /* is udp, parse and remove header */
    if (self->type == UDP_FORWARD) {
        struct socks5hdr hdr;
        struct socks5addr ad;
        ssize_t ret, offset = 0;

        /* if it's a bad packet, drop ,and return -EAGAIN to tell user to retry
         */

        ret = socks5_hdr_get(&hdr, data + offset, nread - offset);
        if (ret == -1)
            return -EAGAIN;
        offset += ret;

        ret = socks5_addr_get(&ad, data + offset, nread - offset);
        if (ret == -1)
            return -EAGAIN;
        offset += ret;

        memmove(data, data + offset, nread - offset);
        nread -= offset;
    }

    return nread;
}

/* impl for struct proxy :: get */
static void socks_get(struct proxy *proxy)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);
    self->refcnt++;
}

/* impl for struct proxy :: put */
static void socks_put(struct proxy *proxy)
{
    struct proxy_socks *self = container_of(proxy, struct proxy_socks, ops);
    if (--self->refcnt == 0) {
        skutils_close_unreg(&self->info, self->loop, &self->sfd);
        free(self->relay);
        free(self->addr);
        free(self->hsbuff);
        free(self);
    }
}

/* global vtable of proxy_socks */
static const struct proxy_ops socks_ops = {
    .shutdown = &socks_shutdown,
    .evctl = &socks_evctl,
    .send = &socks_send,
    .recv = &socks_recv,
    .get = &socks_get,
    .put = &socks_put,
};

/* used for internal only */
static struct proxy_socks *
socks_create_impl(struct loopctx *loop, userev_fn_t *userev, void *userp,
                  int type, const char *addr, uint16_t port,
                  struct proxy_socks *as)
{
    struct proxy_socks *self;
    struct nspconf *conf = current_nspconf();
    uint16_t proxy_port;
    int socktype = (type == UDP_FORWARD) ? SOCK_DGRAM : SOCK_STREAM;

    loglv(3, "socks_create_impl: creating a new struct conn_socks for %s:%u/%s",
             addr, (unsigned)port, (type == UDP_FORWARD) ? "udp" : "tcp");

    if (strlen(addr) > SERVNAME_MAXLEN)
        return NULL;

    if ((self = calloc(1, sizeof(struct proxy_socks))) == NULL)
        oom();
    if ((self->addr = strdup(addr)) == NULL)
        oom();

    /* init */
    self->ops.ops = &socks_ops;
    self->loop = loop;
    self->epcb.on_epoll_events = &socks_epcb_events;
    self->sfd = -1;
    self->events = 0;
    self->refcnt = 1;
    self->userev = userev;
    self->userp = userp;
    self->port = port;
    self->type = type;
    self->relay = NULL;
    self->info.proto = self->type == TCP_FORWARD ? "tcp" : "udp";
    self->info.addr = self->addr;
    self->info.port = self->port;

    if (type == UDP_FORWARD) {
        /* create socket and bind to relay server */
        self->sfd = skutils_connect(&self->info, as->relay->addr,
                                    as->relay->port, SOCK_DGRAM);
        if (self->sfd < 0) {
            free(self->hsbuff);
            free(self->addr);
            free(self);
            return NULL;
        }
        self->phase = PHASE_FORWARDING;

        self->events = EPOLLOUT | EPOLLIN;
        loop_epoll_ctl(self->loop, EPOLL_CTL_ADD, self->sfd, self->events,
                       &self->epcb);
    } else {
        if ((self->hsbuff = buff_calloc(SOCKS_HS_BUFF)) == NULL)
            oom();

        /* connect to proxy server */
        self->sfd = skutils_connect(&self->info, conf->proxysrv,
                                    conf->proxyport, socktype);
        if (self->sfd < 0) {
            free(self->hsbuff);
            free(self->addr);
            free(self);
            return NULL;
        }

        /* wait to handshake */
        self->phase = PHASE_SEND_METHOD;
        loop_epoll_ctl(self->loop, EPOLL_CTL_ADD, self->sfd, EPOLLOUT,
                       &self->epcb);
    }

    return self;
}

/* create a tcp connection
   this connection is proxied via socks server */
struct proxy *socks_tcp_create(struct loopctx *loop, userev_fn_t *userev,
                               void *userp, const char *addr, uint16_t port)
{
    struct proxy_socks *self =
        socks_create_impl(loop, userev, userp, TCP_FORWARD, addr, port, NULL);
    return self ? &self->ops : NULL;
}

/* create a associate connection for udp forward */
struct proxy *socks_assoc_create(struct loopctx *loop, userev_fn_t *userev,
                                 void *userp)
{
    struct proxy_socks *self =
        socks_create_impl(loop, userev, userp, UDP_ASSOCIATE, "0.0.0.0", 0, NULL);
    return self ? &self->ops : NULL;
}

/* create a udp connection
   this connection is proxied via socks server */
struct proxy *socks_udp_create(struct loopctx *loop, userev_fn_t *userev,
                               void *userp, const char *addr, uint16_t port,
                               struct proxy *assoc)
{
    struct proxy_socks *self;
    struct proxy_socks *as = container_of(assoc, struct proxy_socks, ops);

    if (as->phase != PHASE_FORWARDING || as->relay == NULL)
        return NULL;

    self = socks_create_impl(loop, userev, userp, UDP_FORWARD, addr, port, as);

    return self ? &self->ops : NULL;
}
