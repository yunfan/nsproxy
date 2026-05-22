/*
 * Copyright (C) 2023 NaLan ZeYu <nalanzeyu@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "core.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_addr.h"
#include "lwip/ip6_frag.h"
#include "lwip/nd6.h"
#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

#include "direct.h"
#include "http.h"
#include "socks.h"
#include "tcpdns.h"

struct tcp_forward {
    struct corectx *core;
    struct tcp_forward *prev;
    struct tcp_forward *next;
    struct proxy *proxy;
    struct tcp_pcb *pcb;
    struct pbuf *sndq;
    struct pbuf *rcvq;
    unsigned int gc;
    u8_t proxyeof;
    u8_t lwipeof;
    u8_t proxysendeof;
};

struct udp_forward {
    struct corectx *core;
    struct udp_forward *prev;
    struct udp_forward *next;
    struct proxy *proxy;
    struct udp_pcb *pcb;
    struct pbuf *rcvq[8];
    unsigned int gc;
    u16_t nrcvq;
};

struct corectx {
    struct netif tunif;

    struct loopctx *loop;

    int tunfd;
    struct epcb_ops tunepcb;

    int timerfd;
    uint64_t timerepoch;
    struct epcb_ops timerepcb;

    /* tracking all forward instances */
    struct tcp_forward *tcplst;
    struct udp_forward *udplst;

    struct proxy *udpassoc;
    uint32_t assocretries;
    uint32_t assoccd;
    uint8_t assocready;
};

static void udp_assoc_io_event(void *userp, unsigned int events);

static int is_gateway(const struct netif *netif, const ip_addr_t *addr)
{
    return ip_addr_cmp(addr, netif_ip_addr4(netif))
           || ip_addr_cmp(addr, netif_ip_addr6(netif, 0));
}

static int cidr_match_bytes(const uint8_t *addr, const uint8_t *network,
                            uint8_t prefixlen)
{
    uint8_t fullbytes = prefixlen / 8;
    uint8_t rembits = prefixlen % 8;

    if (fullbytes > 0 && memcmp(addr, network, fullbytes) != 0)
        return 0;

    if (rembits > 0) {
        uint8_t mask = (uint8_t)(0xff << (8 - rembits));
        if ((addr[fullbytes] & mask) != (network[fullbytes] & mask))
            return 0;
    }

    return 1;
}

static int is_direct_cidr_target(const ip_addr_t *addr)
{
    struct nspconf *conf = current_nspconf();
    uint8_t raw[16];
    uint8_t family;
    int matched = 0;

    if (conf->direct_cidr_count == 0
        && conf->direct_cidr_mode == DIRECT_CIDR_WHITELIST) {
        return 0;
    }

    memset(raw, 0, sizeof(raw));
    if (IP_IS_V4(addr)) {
        family = AF_INET;
        memcpy(raw, &ip_2_ip4(addr)->addr, 4);
    } else {
        family = AF_INET6;
        memcpy(raw, ip_2_ip6(addr)->addr, 16);
    }

    for (size_t i = 0; i < conf->direct_cidr_count; i++) {
        struct cidr_block *cidr = &conf->direct_cidrs[i];

        if (cidr->family == family
            && cidr_match_bytes(raw, cidr->addr, cidr->prefixlen)) {
            matched = 1;
            break;
        }
    }

    if (conf->direct_cidr_mode == DIRECT_CIDR_BLACKLIST)
        return !matched;

    return matched;
}

static int core_has_pending_udp_assoc(struct corectx *core)
{
    for (struct udp_forward *fwd = core->udplst; fwd; fwd = fwd->next) {
        if (fwd->proxy == NULL)
            return 1;
    }

    return 0;
}

static void core_start_udp_assoc(struct corectx *core)
{
    if (core->udpassoc || core->assocready
        || current_nspconf()->proxytype != PROXY_SOCKS5) {
        return;
    }

    if (core->assoccd > 0)
        return;

    core->udpassoc = socks_assoc_create(core->loop, &udp_assoc_io_event, core);
    core->assocretries++;
    if (core->udpassoc == NULL) {
        int cdexp = core->assocretries <= 5 ? core->assocretries : 5;
        core->assoccd = 1 << cdexp;
    }
}

static uint16_t dns_get_u16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t dns_get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
           | ((uint32_t)p[2] << 8) | p[3];
}

static int dns_read_name(const uint8_t *msg, size_t msglen, size_t *offset,
                         char *out, size_t outlen)
{
    size_t pos = *offset;
    size_t nout = 0;
    int jumped = 0;

    for (unsigned int jumps = 0; jumps < 128; jumps++) {
        uint8_t len;

        if (pos >= msglen)
            return -1;

        len = msg[pos];
        if ((len & 0xc0) == 0xc0) {
            uint16_t ptr;

            if (pos + 1 >= msglen)
                return -1;

            ptr = ((uint16_t)(len & 0x3f) << 8) | msg[pos + 1];
            if (ptr >= msglen)
                return -1;

            if (!jumped) {
                *offset = pos + 2;
                jumped = 1;
            }
            pos = ptr;
            continue;
        }

        if ((len & 0xc0) != 0)
            return -1;

        pos++;
        if (len == 0) {
            if (!jumped)
                *offset = pos;
            if (nout == 0) {
                if (outlen == 0)
                    return -1;
                out[nout++] = '.';
            }
            if (nout >= outlen)
                return -1;
            out[nout] = '\0';
            return 0;
        }

        if (len > 63 || pos + len > msglen)
            return -1;

        if (nout != 0) {
            if (nout + 1 >= outlen)
                return -1;
            out[nout++] = '.';
        }
        if (nout + len >= outlen)
            return -1;

        for (uint8_t i = 0; i < len; i++) {
            uint8_t ch = msg[pos + i];
            if (ch >= 'A' && ch <= 'Z')
                ch = ch - 'A' + 'a';
            out[nout++] = ch;
        }
        pos += len;
    }

    return -1;
}

static int dns_skip_name(const uint8_t *msg, size_t msglen, size_t *offset)
{
    char name[SERVNAME_MAXLEN + 1];
    return dns_read_name(msg, msglen, offset, name, sizeof(name));
}

static const char *dns_qtype_name(uint16_t qtype)
{
    switch (qtype) {
    case 1:
        return "A";
    case 28:
        return "AAAA";
    case 5:
        return "CNAME";
    case 15:
        return "MX";
    case 16:
        return "TXT";
    case 33:
        return "SRV";
    case 65:
        return "HTTPS";
    default:
        return NULL;
    }
}

static void dns_log_query(const char *domain, uint16_t qtype, int matched)
{
    const char *typestr = dns_qtype_name(qtype);
    const char *mode = current_nspconf()->direct_cidr_mode == DIRECT_CIDR_BLACKLIST
                           ? "blacklist"
                           : "whitelist";
    const char *route = matched == (current_nspconf()->direct_cidr_mode
                                    == DIRECT_CIDR_BLACKLIST)
                            ? "proxy"
                            : "direct";

    if (typestr) {
        loglv1("DNS query: %s %s, domain-rule=%s, mode=%s, route=%s", domain,
               typestr, matched ? "matched" : "unmatched", mode, route);
    } else {
        loglv1("DNS query: %s TYPE%u, domain-rule=%s, mode=%s, route=%s",
               domain, (unsigned)qtype, matched ? "matched" : "unmatched",
               mode, route);
    }
}

void nsproxy_log_dns_queries(const char *data, size_t size)
{
    const uint8_t *msg = (const uint8_t *)data;
    uint16_t qdcount;
    size_t offset = 12;

    if (size < 12)
        return;

    qdcount = dns_get_u16(msg + 4);

    for (uint16_t i = 0; i < qdcount; i++) {
        char qname[SERVNAME_MAXLEN + 1];
        uint16_t qtype;
        int qmatched;

        if (dns_read_name(msg, size, &offset, qname, sizeof(qname)) < 0)
            return;
        if (offset + 4 > size)
            return;

        qtype = dns_get_u16(msg + offset);
        qmatched = nspconf_domain_matches(current_nspconf(), qname);
        dns_log_query(qname, qtype, qmatched);

        offset += 4; /* qtype + qclass */
    }
}

static void dns_response_add_direct_cidrs(const char *data, size_t size)
{
    struct nspconf *conf = current_nspconf();
    const uint8_t *msg = (const uint8_t *)data;
    uint16_t flags, qdcount, ancount;
    size_t offset = 12;
    int matched = 0;

    if (conf->direct_domain_count == 0 || size < 12)
        return;

    flags = dns_get_u16(msg + 2);
    if ((flags & 0x8000) == 0)
        return;

    qdcount = dns_get_u16(msg + 4);
    ancount = dns_get_u16(msg + 6);

    for (uint16_t i = 0; i < qdcount; i++) {
        char qname[SERVNAME_MAXLEN + 1];
        uint16_t qtype;
        int qmatched;

        if (dns_read_name(msg, size, &offset, qname, sizeof(qname)) < 0)
            return;
        if (offset + 4 > size)
            return;

        qtype = dns_get_u16(msg + offset);
        qmatched = nspconf_domain_matches(conf, qname);
        if (conf->dnstype != DNS_REDIR_TCP)
            dns_log_query(qname, qtype, qmatched);

        if (qmatched)
            matched = 1;

        offset += 4; /* qtype + qclass */
    }

    if (!matched)
        return;

    for (uint16_t i = 0; i < ancount; i++) {
        uint16_t type, class, rdlen;
        const uint8_t *rdata;

        if (dns_skip_name(msg, size, &offset) < 0)
            return;
        if (offset + 10 > size)
            return;

        type = dns_get_u16(msg + offset);
        class = dns_get_u16(msg + offset + 2);
        (void)dns_get_u32(msg + offset + 4); /* ttl */
        rdlen = dns_get_u16(msg + offset + 8);
        offset += 10;

        if (offset + rdlen > size)
            return;

        rdata = msg + offset;
        if (class == 1 && type == 1 && rdlen == 4) {
            uint8_t addr[16] = { 0 };
            memcpy(addr, rdata, 4);
            nspconf_add_direct_cidr_raw(conf, AF_INET, 32, addr);
        } else if (class == 1 && type == 28 && rdlen == 16) {
            uint8_t addr[16] = { 0 };
            memcpy(addr, rdata, 16);
            nspconf_add_direct_cidr_raw(conf, AF_INET6, 128, addr);
        }

        offset += rdlen;
    }
}

static void tun_input(struct netif *tunif)
{
    struct corectx *core = tunif->state;
    struct pbuf *p = NULL;

    for (;;) {
        ssize_t nread;

        if ((p = pbuf_alloc(PBUF_RAW, NSPROXY_MTU, PBUF_RAM)) == NULL)
            oom();

        nread = read(core->tunfd, p->payload, p->len);
        if (nread == -1 && errno == EAGAIN) {
            break;
        } else if (nread == -1) {
            logwarn("tun_input: read tunfd failed: %s", strerror(errno));
            break;
        }

        loginfo("tun_input: read %zd bytes from TUN", nread);

        /* shrink, set p->tot_len = nread */
        pbuf_realloc(p, nread);

        if (tunif->input(p, tunif) != ERR_OK) {
            LWIP_DEBUGF(NETIF_DEBUG, ("tun_input: netif input error\n"));
            break;
        }

        p = NULL; /* ownship was moved to tunif */
    }

    if (p)
        pbuf_free(p);
}

static err_t tun_output(struct netif *tunif, struct pbuf *p)
{
    struct corectx *core = tunif->state;
    struct pbuf *seg;
    struct iovec iov[16];
    size_t i, clen;
    ssize_t nwrite;

    clen = pbuf_clen(p);

    if (clen > arraysizeof(iov) || p->tot_len > NSPROXY_MTU) {
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: packet too large\n"));
        return ERR_IF;
    }

    /* iov = segments in pbuf */
    for (seg = p, i = 0; i < clen; i++) {
        iov[i].iov_base = seg->payload;
        iov[i].iov_len = seg->len;
        seg = seg->next;
    }

    nwrite = writev(core->tunfd, iov, clen);
    if (nwrite == -1 && errno == EAGAIN) {
        /* ERR_OK is same as frame dropped at link-layer. This is fine since TUN
           almost never returns EAGAIN with default settings */
        logwarn("tun_output: tunfd EAGAIN");
        return ERR_OK;
    } else if (nwrite == -1) {
        logwarn("tun_output: writev tunfd failed: %s", strerror(errno));
        return ERR_IF;
    } else if (nwrite != p->tot_len) {
        /* should not happen, we have checked p->tot_len <= MTU */
        LWIP_DEBUGF(NETIF_DEBUG, ("tun_output: partial write\n"));
        return ERR_IF;
    }

    loginfo("tun_output: wrote %zd bytes to TUN", nwrite);

    return ERR_OK;
}

static err_t tunip4_output(struct netif *netif, struct pbuf *p,
                           const ip4_addr_t *ipaddr)
{
    return tun_output(netif, p);
}

static err_t tunip6_output(struct netif *netif, struct pbuf *p,
                           const ip6_addr_t *ipaddr)
{
    return tun_output(netif, p);
}

static err_t tunlink_output(struct netif *tunif, struct pbuf *packet)
{
    logwarn("tunlink_output: netif->linkoutput called unexpectedly, drop.");
    return ERR_IF;
}

static err_t tunif_init(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'u';

    netif->output = tunip4_output;
    netif->output_ip6 = tunip6_output;
    netif->linkoutput = tunlink_output;
    netif->mtu = NSPROXY_MTU;

    return ERR_OK;
}

static void core_tunfd_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct corectx *core = container_of(epcb, struct corectx, tunepcb);
    tun_input(&core->tunif);
}

/* Create a new udp_forward instance and add to list */
static struct udp_forward *udp_forward_create(struct corectx *core)
{
    struct udp_forward *fwd = calloc(1, sizeof(*fwd));
    if (fwd == NULL)
        oom();

    fwd->core = core;
    fwd->gc = NSPROXY_UDP_IDLE_TIMEOUT;

    /* add to head */
    fwd->next = core->udplst;
    if (core->udplst != NULL) {
        core->udplst->prev = fwd;
    }
    core->udplst = fwd;

    return fwd;
}

/* Destroy a udp_forward instance and remove from list */
static void udp_forward_destroy(struct udp_forward *fwd)
{
    struct corectx *core = fwd->core;

    /* remove from linked-list */
    if (fwd->prev != NULL) {
        fwd->prev->next = fwd->next;
    } else {
        core->udplst = fwd->next;
    }
    if (fwd->next != NULL) {
        fwd->next->prev = fwd->prev;
    }

    /* free receive queue */
    while (fwd->nrcvq --> 0) /* out of tricks, it's time to bite a lighter */
        pbuf_free(fwd->rcvq[fwd->nrcvq]);

    if (fwd->pcb) {
        udp_recv(fwd->pcb, NULL, NULL);
        udp_remove(fwd->pcb);
    }

    if (fwd->proxy)
        proxy_put(fwd->proxy);

    free(fwd);
}

/* Try to recv data from proxy server and send to application
   If return value is not ERR_OK, fwd was free'ed, caller should not continue */
static err_t udp_proxy_input(struct udp_forward *fwd)
{
    struct proxy *proxy = fwd->proxy;
    struct udp_pcb *pcb = fwd->pcb;
    char *buffer;
    struct pbuf *p = NULL;
    err_t ret;

    fwd->gc = fwd->pcb->local_port == 53 ? NSPROXY_DNS_IDLE_TIMEOUT
                                         : NSPROXY_UDP_IDLE_TIMEOUT;

    if ((buffer = malloc(UDP_PACKET_MAXLEN)) == NULL)
        oom();

    for (;;) {
        err_t err;
        ssize_t nread;

        p = pbuf_alloc_reference(buffer, UDP_PACKET_MAXLEN, PBUF_REF);
        if (p == NULL)
            oom();

        nread = proxy_recv(proxy, p->payload, p->len);
        if (nread == -EAGAIN) {
            proxy_evctl(proxy, EPOLLIN, EVSET);
            ret = ERR_OK;
            break;
        } else if (nread < 0) {
            logwarn("udp_proxy_input: proxy error, destroy fwd, reason: %s",
                    strerror(-nread));
            udp_forward_destroy(fwd);
            ret = ERR_ABRT;
            break;
        }

        if (fwd->pcb->local_port == 53)
            dns_response_add_direct_cidrs(buffer, nread);

        pbuf_realloc(p, nread); /* set p->tot_len = nread */
        err = udp_send(pcb, p);
        if (err != ERR_OK && err != ERR_MEM) {
            logwarn("udp_proxy_input: udp_send() failed, destroy fwd");
            udp_forward_destroy(fwd);
            ret = ERR_ABRT;
            break;
        }
        /* ERR_MEM: TX queue full, ignore and drop */

        /* tun_output() is synchronous, reuse pbuf is possile, but we follow
           lwIP API semantics: call pbuf_free() immediately after udp_send().
           But recycle buffer is safe, PBUF_REF is volatile and lwIP will copy
           data if they need. */
        pbuf_free(p);
        p = NULL;
    }

    if (p)
        pbuf_free(p);
    free(buffer);

    return ret;
}

/* Try to send data to proxy server, data already in fwd->rcvq
   If return value is not ERR_OK, fwd was free'ed, caller should not continue */
static err_t udp_proxy_output(struct udp_forward *fwd)
{
    struct proxy *proxy = fwd->proxy;
    ssize_t i, nsent;
    struct pbuf *p;
    char *heapbuff = NULL;

    fwd->gc = fwd->pcb->local_port == 53 ? NSPROXY_DNS_IDLE_TIMEOUT
                                         : NSPROXY_UDP_IDLE_TIMEOUT;

    /* send all */
    for (i = 0; i < fwd->nrcvq; i++) {
        p = fwd->rcvq[i];
        if (p->len == p->tot_len) {
            /* only single pbuf in chain */
            nsent = proxy_send(proxy, p->payload, p->tot_len);
        } else {
            char stkbuff[2048];
            if (p->tot_len <= sizeof(stkbuff)) {
                /* prefer use stack buffer */
                pbuf_copy_partial(p, stkbuff, p->tot_len, 0);
                nsent = proxy_send(proxy, stkbuff, p->tot_len);
            } else {
                if (heapbuff == NULL) {
                    if ((heapbuff = malloc(UDP_PACKET_MAXLEN)) == NULL)
                        oom();
                }
                pbuf_copy_partial(p, heapbuff, p->tot_len, 0);
                nsent = proxy_send(proxy, heapbuff, p->tot_len);
            }
        }
        /* EAGAIN is not fatal error, and will not handle in UDP, ignore */
        if (nsent < 0 && nsent != -EAGAIN) {
            logwarn("udp_proxy_output: proxy error, force destroy fwd, "
                    "reason: %s", strerror(-nsent));
            goto failed_abort;
        }
        /* don't pbuf_free(p) here, if some packet sent succeed and some failed,
           it will leave a half-free'ed rcvq. */
    }

    for (i = 0; i < fwd->nrcvq; i++)
        pbuf_free(fwd->rcvq[i]);
    fwd->nrcvq = 0;

    /* rcvq drained */
    proxy_evctl(proxy, EPOLLOUT, EVCLR);

    free(heapbuff);
    return ERR_OK;

failed_abort:
    udp_forward_destroy(fwd);
    free(heapbuff);
    return ERR_ABRT;
}

/* called by lwip when data has received from application,
   this function push the received data to receive queue
*/
static void udp_lwip_received(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                              const ip_addr_t *addr, u16_t port)
{
    struct udp_forward *fwd = arg;

    if (!p) { /* should not happen */
        udp_forward_destroy(fwd);
        return;
    }

    if (fwd->nrcvq == arraysizeof(fwd->rcvq)) {
        /* receive queue full, drop oldest data in queue and enqueue this */
        pbuf_free(fwd->rcvq[0]);
        memmove(fwd->rcvq, fwd->rcvq + 1,
                (arraysizeof(fwd->rcvq) - 1) * sizeof(fwd->rcvq[0]));
        fwd->rcvq[arraysizeof(fwd->rcvq) - 1] = p;
    } else {
        fwd->rcvq[fwd->nrcvq++] = p;
    }

    if (fwd->proxy)
        udp_proxy_output(fwd);
}

/* handle event occured in connection connected to proxy server */
static void udp_proxy_io_event(void *userp, unsigned int events)
{
    struct udp_forward *fwd = userp;
    err_t err = ERR_OK;

    if (!err && (events & EPOLLIN))
        err = udp_proxy_input(fwd);

    if (!err && (events & EPOLLOUT))
        err = udp_proxy_output(fwd);

    if (!err && (events & EPOLLERR))
        udp_forward_destroy(fwd);
}

/* called by lwip when a udp connection is create
   this function create a connection to proxy server and set lwip udp_recv() up
*/
err_t core_udp_new(struct udp_pcb *pcb)
{
    struct corectx *core = ip_current_netif()->state;
    struct nspconf *conf = current_nspconf();
    struct udp_forward *fwd;
    char ip[IPADDR_STRLEN_MAX + 1];
    const char *route = "unknown";

    fwd = udp_forward_create(core);
    fwd->pcb = pcb;
    fwd->gc = pcb->local_port == 53 ? NSPROXY_DNS_IDLE_TIMEOUT
                                    : NSPROXY_UDP_IDLE_TIMEOUT;

    udp_recv(pcb, udp_lwip_received, fwd);

    /* DNS redirection */
    if (is_gateway(&core->tunif, &pcb->local_ip) && pcb->local_port == 53
        && conf->dnstype != DNS_REDIR_OFF) {
        if (conf->dnstype == DNS_REDIR_TCP)
            fwd->proxy = tcpdns_create(core->loop, &udp_proxy_io_event, fwd);
        else
            fwd->proxy = direct_udp_create(core->loop, &udp_proxy_io_event, fwd,
                                           conf->dnssrv, conf->dnsport);
        goto end;
    }

    /* forward gateway to host namespace  */
    if (is_gateway(&core->tunif, &pcb->local_ip)) {
        const char *localhost = IP_IS_V4(&pcb->local_ip) ? "127.0.0.1" : "::1";
        fwd->proxy = direct_udp_create(core->loop, &udp_proxy_io_event, fwd,
                                       localhost, pcb->local_port);
        goto end;
    }

    ipaddr_ntoa_r(&pcb->local_ip, ip, sizeof(ip));
    if (is_direct_cidr_target(&pcb->local_ip)) {
        route = "direct";
        fwd->proxy = direct_udp_create(core->loop, &udp_proxy_io_event, fwd, ip,
                                       pcb->local_port);
    } else if (conf->proxytype == PROXY_SOCKS5 && !core->assocready) {
        /* leave a pending fwd */
        fwd->proxy = NULL;
        core_start_udp_assoc(core);
        return ERR_OK;
    } else if (conf->proxytype == PROXY_SOCKS5) {
        route = "socks5";
        fwd->proxy = socks_udp_create(core->loop, &udp_proxy_io_event, fwd, ip,
                                      pcb->local_port, core->udpassoc);
    } else if (conf->proxytype == PROXY_DIRECT) {
        route = "direct";
        fwd->proxy = direct_udp_create(core->loop, &udp_proxy_io_event, fwd, ip,
                                       pcb->local_port);
    } else if (conf->proxytype == PROXY_HTTP) {
        route = "http";
    }

end:
    if (fwd->proxy == NULL) {
        ipaddr_ntoa_r(&pcb->local_ip, ip, sizeof(ip));
        loglv1("Access: target=%s:%u proto=udp route=%s result=failed "
               "reason=route-unavailable", ip, (unsigned)pcb->local_port,
               route);
        udp_forward_destroy(fwd);
        return ERR_ABRT;
    } else {
        return ERR_OK;
    }
}

/* handle events in in struct proxy, for UDP associate connection */
static void udp_assoc_io_event(void *userp, unsigned int events)
{
    struct corectx *core = userp;
    struct udp_forward *fwd;

    /* unexpected events on udpassoc connection, clean up and set countdown */
    if (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
        int cdexp = core->assocretries <= 5 ? core->assocretries : 5;

        proxy_put(core->udpassoc);
        core->udpassoc = NULL;
        core->assocready = 0;
        core->assoccd = 1 << cdexp; /* exponent backoff */

        for (fwd = core->udplst; fwd;) {
            struct udp_forward *next = fwd->next;
            struct udp_pcb *pcb = fwd->pcb;
            char ip[IPADDR_STRLEN_MAX + 1];

            if (fwd->proxy) {
                fwd = next;
                continue;
            }

            ipaddr_ntoa_r(&pcb->local_ip, ip, sizeof(ip));
            loglv1("Access: target=%s:%u proto=udp route=socks5 result=failed "
                   "reason=socks5-udp-associate-failed", ip,
                   (unsigned)pcb->local_port);
            udp_forward_destroy(fwd);
            fwd = next;
        }

        return;
    }

    /* interest on EPOLLOUT only once, so now assoc just succeed */
    proxy_evctl(core->udpassoc, EPOLLOUT, EVCLR);
    core->assocready = 1;
    core->assocretries = 0;

    /* connect to proxy for pending fwd */
    for (fwd = core->udplst; fwd;) {
        struct udp_pcb *pcb = fwd->pcb;
        char ip[IPADDR_STRLEN_MAX + 1];
        struct udp_forward *next;

        if (fwd->proxy) { /* not pending */
            fwd = fwd->next;
            continue;
        }

        next = fwd->next;
        ipaddr_ntoa_r(&pcb->local_ip, ip, sizeof(ip));
        const char *route;
        if (is_direct_cidr_target(&pcb->local_ip)) {
            route = "direct";
            fwd->proxy = direct_udp_create(core->loop, &udp_proxy_io_event, fwd,
                                           ip, pcb->local_port);
        } else {
            route = "socks5";
            fwd->proxy = socks_udp_create(core->loop, &udp_proxy_io_event, fwd,
                                          ip, pcb->local_port, core->udpassoc);
        }
        if (fwd->proxy == NULL) {
            loglv1("Access: target=%s:%u proto=udp route=%s result=failed "
                   "reason=route-unavailable", ip, (unsigned)pcb->local_port,
                   route);
            udp_forward_destroy(fwd);
            fwd = next;
            continue;
        }

        if (fwd->nrcvq > 0 && udp_proxy_output(fwd) != ERR_OK) {
            fwd = next;
            continue;
        }

        fwd = next;
    }
}

/* Create a new tcp_forward instance and add to list */
static struct tcp_forward *tcp_forward_create(struct corectx *core)
{
    struct tcp_forward *fwd = calloc(1, sizeof(*fwd));
    if (fwd == NULL)
        oom();

    fwd->core = core;
    fwd->gc = NSPROXY_TCP_IDLE_TIMEOUT;

    /* add to head */
    fwd->next = core->tcplst;
    if (core->tcplst != NULL) {
        core->tcplst->prev = fwd;
    }
    core->tcplst = fwd;

    return fwd;
}

/* Destroy a tcp_forward instance and remove from list */
static void tcp_forward_destroy(struct tcp_forward *fwd, int force)
{
    struct corectx *core = fwd->core;
    int rst = 0;

    /* queues not drained, breaks TCP reliable delivery semantics, RST */
    if (fwd->sndq != NULL || fwd->rcvq != NULL)
        rst = 1;

    /* remove from linked-list */
    if (fwd->prev != NULL)
        fwd->prev->next = fwd->next;
    else
        core->tcplst = fwd->next;
    if (fwd->next != NULL)
        fwd->next->prev = fwd->prev;

    if (fwd->pcb) {
        /* avoid tcp_close() calls callbacks again on destroy path */
        tcp_arg(fwd->pcb, NULL);
        tcp_sent(fwd->pcb, NULL);
        tcp_recv(fwd->pcb, NULL);
        tcp_err(fwd->pcb, NULL);
        if (force || rst) {
            tcp_abort(fwd->pcb);
        } else {
            if (tcp_close(fwd->pcb) != ERR_OK)
                tcp_abort(fwd->pcb); /* tcp_close() may failed, abort it. */
        }
    }

    if (fwd->proxy) {
        if (force || rst)
            proxy_shutdown(fwd->proxy, SHUT_RDWR, 1);
        proxy_put(fwd->proxy);
    }

    if (fwd->sndq)
        pbuf_free(fwd->sndq);
    if (fwd->rcvq)
        pbuf_free(fwd->rcvq);

    free(fwd);
}

/* Try to recv data from proxy server and send to application
   May called from lwip context if
   - data are ack'ed by lwip
   May called from epoll context if
   - data are received from proxy server, in socket buffer
   - EOF is received from proxy server
   If return value is not ERR_OK, fwd was free'ed, caller should not continue */
static err_t tcp_proxy_input(struct tcp_forward *fwd)
{
    struct tcp_pcb *pcb = fwd->pcb;
    struct proxy *proxy = fwd->proxy;
    struct pbuf *p;

    fwd->gc = NSPROXY_TCP_IDLE_TIMEOUT;

    while (!fwd->proxyeof && tcp_sndbuf(pcb) > tcp_mss(pcb)
           && tcp_sndqueuelen(pcb) <= TCP_SND_QUEUELEN / 2) {
        ssize_t nread;

        if ((p = pbuf_alloc(PBUF_RAW, tcp_mss(pcb), PBUF_RAM)) == NULL)
            oom();

        nread = proxy_recv(proxy, p->payload, p->len);
        if (nread == -EAGAIN) {
            proxy_evctl(proxy, EPOLLIN, EVSET);
            pbuf_free(p);
            return ERR_OK;
        } else if (nread < 0) {
            logwarn("tcp_proxy_input: proxy error, force destroy fwd "
                    "reason: %s", strerror(-nread));
            goto failed_after_pbuf_alloc;
        } else if (nread == 0) {
            loginfo("tcp_proxy_input: received EOF from proxy");
            fwd->proxyeof = 1;
            pbuf_free(p);
            break;
        } else {
            pbuf_realloc(p, nread); /* set to actual length */

            /* send and leave data stay in sndq, free after ACK */
            if (tcp_write(pcb, p->payload, nread, 0) != ERR_OK) {
                logwarn("tcp_proxy_input: tcp_write() failed");
                goto failed_after_pbuf_alloc;
            }
            if (fwd->sndq == NULL)
                fwd->sndq = p;
            else
                pbuf_cat(fwd->sndq, p);

            /* Typically tcp_write() + tcp_output() calling sequence.
               Failures are ignored since tcp_tmr() will auto retry as long as
               data was enqueued by tcp_write() */
            tcp_output(pcb);
        }
    }

    /* no space in sndq available or proxy EOF, stop polling EPOLLIN */
    proxy_evctl(proxy, EPOLLIN, EVCLR);

    /* received EOF from proxy, and all datas has been sent to lwip,
       forward this EOF to lwip now */
    if (fwd->proxyeof && !fwd->sndq) {
        loginfo("tcp_proxy_input: sndq drained, half-closing lwip");
        tcp_shutdown(pcb, 0, 1);
        if (fwd->lwipeof && !fwd->rcvq) {
            loginfo("tcp_proxy_input: full-closing");
            tcp_forward_destroy(fwd, 0);
            return ERR_CLSD;
        }
    }

    return ERR_OK;

failed_after_pbuf_alloc:
    pbuf_free(p);
    tcp_forward_destroy(fwd, 1);
    return ERR_ABRT;
}

/* Try to send data to proxy server
   Called from lwip context if
   - data are received from lwip, in fwd->rcvq
   - EOF is received from lwip
   Called from epoll context if:
   - there is some free space available in socket buffer
   If return value is not ERR_OK, fwd was free'ed, caller should not continue
*/
static err_t tcp_proxy_output(struct tcp_forward *fwd)
{
    struct tcp_pcb *pcb = fwd->pcb;
    struct proxy *proxy = fwd->proxy;
    ssize_t nsent;

    fwd->gc = NSPROXY_TCP_IDLE_TIMEOUT;

    while (fwd->rcvq) {
        nsent = proxy_send(proxy, fwd->rcvq->payload, fwd->rcvq->len);
        if (nsent == -EAGAIN) {
            proxy_evctl(proxy, EPOLLOUT, EVSET);
            return ERR_OK;
        } else if (nsent < 0) {
            logwarn("tcp_proxy_output: proxy error, force destroy fwd, "
                    "reason: %s", strerror(-nsent));
            tcp_forward_destroy(fwd, 1);
            return ERR_ABRT;
        } else {
            fwd->rcvq = pbuf_free_header(fwd->rcvq, nsent);
            tcp_recved(pcb, nsent);
        }
    }

    /* rcvq drained */
    proxy_evctl(proxy, EPOLLOUT, EVCLR);

    /* received EOF from lwip, and all datas has been sent to proxy,
       forward this EOF to proxy now */
    if (fwd->lwipeof && !fwd->proxysendeof) {
        if (current_nspconf()->no_proxy_half_close) {
            loginfo("tcp_proxy_output: rcvq drained, proxy half-close disabled");
            fwd->proxysendeof = 1;
        } else {
            int ret;

            loginfo("tcp_proxy_output: rcvq drained, half-closing proxy");
            ret = proxy_shutdown(proxy, SHUT_WR, 0);
            if (ret == -EAGAIN) {
                proxy_evctl(proxy, EPOLLOUT, EVSET);
                return ERR_OK;
            } else if (ret < 0) {
                logwarn("tcp_proxy_output: proxy shutdown failed, force destroy "
                        "fwd, reason: %s", strerror(-ret));
                tcp_forward_destroy(fwd, 1);
                return ERR_ABRT;
            }
            fwd->proxysendeof = 1;
        }
        /* full close */
        if (fwd->proxyeof && !fwd->sndq) {
            loginfo("tcp_proxy_output: full-closing");
            tcp_forward_destroy(fwd, 0);
            return ERR_CLSD;
        }
    }

    return ERR_OK;
}

/* called by lwip when application acked data,
   this function free sending queue, and ask more data from proxy server
*/
static err_t tcp_lwip_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    struct tcp_forward *fwd = arg;

    /* remove ack'ed data from send queue */
    fwd->sndq = pbuf_free_header(fwd->sndq, len);

    /* ask proxy server for more data, if we have space in queue */
    if (tcp_sndbuf(pcb) >= TCPWND16(TCP_SND_BUF / 2))
        if (tcp_sndqueuelen(pcb) <= TCP_SND_QUEUELEN / 2)
            return tcp_proxy_input(fwd);

    return ERR_OK;
}

/* called by lwip when data has received from application,
   this function push the these data to receive queue
*/
static err_t tcp_lwip_received(void *arg, struct tcp_pcb *pcb, struct pbuf *p,
                               err_t err)
{
    struct tcp_forward *fwd = arg;
    err_t ret;

    if (p) {
        /* here's some data need enqueue, rcvq should not full */
        if (fwd->rcvq)
            pbuf_cat(fwd->rcvq, p);
        else
            fwd->rcvq = p;
    } else {
        loginfo("tcp_lwip_received: received EOF from lwip");
        fwd->lwipeof = 1;
    }

    ret = tcp_proxy_output(fwd);

    if (ret == ERR_OK)
        tcp_ack(pcb); /* ack immediately */

    return ret;
}

/* called by lwip when TCP connection has been destroyed,
   just destroy tcp_forward but remember that PCB has been gone
*/
static void tcp_lwip_err(void *arg, err_t err)
{
    struct tcp_forward *fwd = arg;
    if (fwd) {
        logwarn("tcp_lwip_err: lwip error, force destroy fwd");
        fwd->pcb = NULL;
        tcp_forward_destroy(fwd, 1);
    }
}

/* handle events occured in connection connected to proxy server */
static void tcp_proxy_io_event(void *userp, unsigned int events)
{
    struct tcp_forward *fwd = userp;
    err_t err = ERR_OK;

    /* There's may some confuse that we don't care EPOLLERR here. We add fd to
       epoll instance iff we are interested in either EPOLLIN or EPOLLOUT, which
       is always return together with EPOLLERR if socket error. (see select(2)).
       That's means socket error will be handled in tcp_proxy_{input|output}
       Ignore EPOLLERR here not only for reduce codes in error path, but also
       avoid data lost if proxy sent DATA+RST */
    if (events & EPOLLERR)
        assert(events & (EPOLLIN | EPOLLOUT)); /* note that fact to you */

    if (!err && (events & EPOLLIN))
        err = tcp_proxy_input(fwd);

    if (!err && (events & EPOLLOUT))
        err = tcp_proxy_output(fwd);

    if (!err && !fwd->pcb->proxyestab) {
        /* SYN+ACK is delayed until proxy established, send it now */
        fwd->pcb->proxyestab = 1;
        tcp_output(fwd->pcb);
    }
}

/* called by lwip when a tcp connection is create
   this function create a connection to proxy server and set lwip tcp_*() up
*/
err_t core_tcp_new(struct tcp_pcb *pcb)
{
    struct corectx *core = ip_current_netif()->state;
    struct nspconf *conf = current_nspconf();
    struct tcp_forward *fwd;
    char ip[IPADDR_STRLEN_MAX + 1];

    fwd = tcp_forward_create(core);
    fwd->pcb = pcb;

    tcp_nagle_disable(pcb);
    tcp_arg(pcb, fwd);
    tcp_sent(pcb, &tcp_lwip_sent);
    tcp_recv(pcb, &tcp_lwip_received);
    tcp_err(pcb, &tcp_lwip_err);

    /* forward gateway to host namespace  */
    if (is_gateway(&core->tunif, &pcb->local_ip)) {
        const char *localhost = IP_IS_V4(&pcb->local_ip) ? "127.0.0.1" : "::1";
        fwd->proxy = direct_tcp_create(core->loop, &tcp_proxy_io_event, fwd,
                                       localhost, pcb->local_port);
        goto end;
    }

    ipaddr_ntoa_r(&pcb->local_ip, ip, sizeof(ip));
    if (is_direct_cidr_target(&pcb->local_ip)) {
        fwd->proxy = direct_tcp_create(core->loop, &tcp_proxy_io_event, fwd, ip,
                                       pcb->local_port);
    } else if (conf->proxytype == PROXY_SOCKS5) {
        fwd->proxy = socks_tcp_create(core->loop, &tcp_proxy_io_event, fwd, ip,
                                      pcb->local_port);
    } else if (conf->proxytype == PROXY_HTTP) {
        fwd->proxy = http_tcp_create(core->loop, &tcp_proxy_io_event, fwd, ip,
                                     pcb->local_port);
    } else {
        fwd->proxy = direct_tcp_create(core->loop, &tcp_proxy_io_event, fwd, ip,
                                       pcb->local_port);
    }

end:
    if (fwd->proxy == NULL) {
        tcp_forward_destroy(fwd, 1);
        return ERR_ABRT;
    } else {
        return ERR_OK;
    }
}

/* call every 1s */
static void core_gc_tmr(struct corectx *core)
{
    struct tcp_forward *tcur = core->tcplst;
    struct udp_forward *ucur = core->udplst;

    while (tcur) {
        struct tcp_forward *next = tcur->next;
        if (tcur->gc-- == 0)
            tcp_forward_destroy(tcur, 1);
        tcur = next;
    }

    while (ucur) {
        struct udp_forward *next = ucur->next;
        if (ucur->gc-- == 0)
            udp_forward_destroy(ucur);
        ucur = next;
    }
}

/* call every 1s */
static void core_reassoc_tmr(struct corectx *core)
{
    if (current_nspconf()->proxytype != PROXY_SOCKS5)
        return;

    if (core->udpassoc == NULL && !core->assocready
        && core_has_pending_udp_assoc(core)) {
        /* re-associate is needed */
        if (core->assoccd > 0) {
            /* exponent backoff countdown */
            core->assoccd--;
        } else {
            /* re-associate */
            core_start_udp_assoc(core);
        }
    }
}

/* call every 250ms */
static void core_timerfd_epcb_events(struct epcb_ops *epcb, unsigned int events)
{
    struct corectx *core = container_of(epcb, struct corectx, timerepcb);
    uint64_t expired;

    if (read(core->timerfd, &expired, sizeof(expired)) == -1) {
        logwarn("core_timerfd_epcb_events: read timerfd failed: %s",
                strerror(errno));
        return;
    }
    while (expired--) {
        if (core->timerepoch % 4 == 0) {
            core_gc_tmr(core);
            core_reassoc_tmr(core);
            ip_reass_tmr();
            ip6_reass_tmr();
            nd6_tmr();
        }
        tcp_tmr();
        core->timerepoch++;
    }
}

int core_init(struct corectx **core, struct loopctx *loop, int tunfd)
{
    struct corectx *p;
    ip4_addr_t tunaddr;
    ip4_addr_t tunnetmask;
    ip4_addr_t tungateway;
    ip6_addr_t tunaddr6;
    struct itimerspec its = { .it_interval.tv_nsec = 250000000,
                              .it_value.tv_nsec = 250000000 };

    if ((p = calloc(1, sizeof(struct corectx))) == NULL)
        oom();

    p->tunfd = tunfd;
    p->loop = loop;

    /* lwip required call to some functions periodically every 250ms */
    if ((p->timerfd = timerfd_create(CLOCK_MONOTONIC,
                                     TFD_NONBLOCK | TFD_CLOEXEC)) == -1) {
        loglv0("core_init: timerfd_create() failed: %s", strerror(errno));
        goto failed_after_malloc;
    }
    if ((timerfd_settime(p->timerfd, 0, &its, NULL)) == -1) {
        loglv0("core_init: timerfd_settime() failed: %s", strerror(errno));
        goto failed_after_timerfd_create;
    }

    /* register tunfd to epoll */
    p->tunepcb.on_epoll_events = &core_tunfd_epcb_events;
    if (loop_epoll_ctl(loop, EPOLL_CTL_ADD, tunfd, EPOLLIN, &p->tunepcb) < 0)
        goto failed_after_timerfd_create;

    /* register timerfd to epoll */
    p->timerepcb.on_epoll_events = &core_timerfd_epcb_events;
    if (loop_epoll_ctl(loop, EPOLL_CTL_ADD, p->timerfd, EPOLLIN,
                       &p->timerepcb) < 0)
        goto failed_after_timerfd_create;

    lwip_init();
    ip4addr_aton(NSPROXY_GATEWAY_IP, &tunaddr);
    ip4addr_aton(NSPROXY_NETMASK, &tunnetmask);
    ip4addr_aton("0.0.0.0", &tungateway);

    netif_add(&p->tunif, &tunaddr, &tunnetmask, &tungateway, p, &tunif_init,
              &ip_input);
    netif_set_default(&p->tunif);
    netif_set_link_up(&p->tunif);
    netif_set_up(&p->tunif);

    if (current_nspconf()->ipv6) {
        ip6addr_aton(NSPROXY_GATEWAY_IPV6, &tunaddr6);
        netif_ip6_addr_set(&p->tunif, 0, &tunaddr6);
        netif_ip6_addr_set_state(&p->tunif, 0, IP6_ADDR_PREFERRED);
    }

    loginfo("core_init: initialized lwIP core forwarding module (corectx)");

    if (current_nspconf()->proxytype == PROXY_DIRECT) {
        p->udpassoc = NULL;
        p->assocready = 1;
    } else {
        p->udpassoc = NULL;
        p->assocready = 0;
    }
    p->assocretries = 0;
    p->assoccd = 0;

    *core = p;
    return 0;

failed_after_timerfd_create:
    close(p->timerfd);
failed_after_malloc:
    free(p);
    return -1;
}

void core_deinit(struct corectx *core)
{
    while (core->tcplst)
        tcp_forward_destroy(core->tcplst, 1);
    while (core->udplst)
        udp_forward_destroy(core->udplst);

    if (core->udpassoc)
        proxy_put(core->udpassoc);

    netif_remove(&core->tunif);

    if (close(core->timerfd))
        loglv0("core_deinit: timerfd close() failed: %s", strerror(errno));

    free(core);
}
