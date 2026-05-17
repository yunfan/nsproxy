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
#pragma once

#define NSPROXY_MODIFIED 1

/* MTU for Linux TUN and lwIP netif */
#define NSPROXY_MTU        36000

/* IPv4 CGNAT 100.64.0.0-100.127.255.255 */
#define NSPROXY_GATEWAY_IP "100.64.1.1"
#define NSPROXY_LOCAL_IP   "100.64.1.2"
#define NSPROXY_NETMASK    "255.255.255.252"

/* IPv6 ULA */
#define NSPROXY_GATEWAY_IPV6 "fd00:100:64:1::1"
#define NSPROXY_LOCAL_IPV6   "fd00:100:64:1::2"
#define NSPROXY_PREFIXLEN    64

#define NSPROXY_TCP_IDLE_TIMEOUT 7206
#define NSPROXY_UDP_IDLE_TIMEOUT 302
#define NSPROXY_DNS_IDLE_TIMEOUT 16

/* Use lwIP low-level raw API only
   nsproxy hacked into lwIP internal, raw API is more predictable */
#define NO_SYS       1
#define LWIP_SOCKET  0
#define LWIP_NETCONN 0

/* Enable modules: IPv4 / IPv6 / ICMP / UDP / TCP */
#define LWIP_ARP      0
#define LWIP_ETHERNET 0
#define LWIP_IPV4     1
#define LWIP_ICMP     1
#define LWIP_IGMP     0
#define LWIP_RAW      0
#define LWIP_UDP      1
#define LWIP_UDPLITE  0
#define LWIP_TCP      1
#define LWIP_IPV6     1
#define LWIP_ICMP6    1
#define LWIP_IPV6_MLD 0
#define LWIP_STATS    0
#define LWIP_TIMERS   0

/* Use glibc malloc() / free()
   lwIP memory pool has been trimmed for simplicity. Performance profiler shows
   it's not a bottleneck, and barely visible on the flame graph.
*/
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1

#define MEM_ALIGNMENT __SIZEOF_POINTER__

/* netif */
#define LWIP_SINGLE_NETIF   1
#define LWIP_MULTICAST_PING 1
#define PBUF_LINK_HLEN      0

/* IPv4 */
#define IP_FORWARD 0

/* IPv6 */
#define LWIP_IPV6_FORWARD             0
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS 0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0
#define LWIP_IPV6_AUTOCONFIG          0
#define IPV6_FRAG_COPYHEADER          1

/* TCP tuning */
#define TCP_MSS          (NSPROXY_MTU-60)
#define TCP_WND          (TCP_MSS*2)
#define TCP_SND_BUF      (TCP_MSS*2)
#define TCP_SND_QUEUELEN 65535
#define LWIP_WND_SCALE   1
#define TCP_RCV_SCALE    1

#ifdef NDEBUG
#define LWIP_DEBUG 0
#else
#define LWIP_DEBUG 1
#endif

/* Debug mode */
#if LWIP_DEBUG
#define IP_DEBUG         LWIP_DBG_OFF
#define IP6_DEBUG        LWIP_DBG_OFF
#define ICMP_DEBUG       LWIP_DBG_OFF
#define TCP_DEBUG        LWIP_DBG_OFF
#define UDP_DEBUG        LWIP_DBG_OFF
#define NETIF_DEBUG      LWIP_DBG_OFF
#define TIMERS_DEBUG     LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG LWIP_DBG_OFF
#endif

#define SYS_ARCH_DECL_PROTECT(lev) (void)0
#define SYS_ARCH_PROTECT(lev)      (void)0
#define SYS_ARCH_UNPROTECT(lev)    (void)0

#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1
#define lwip_htons(x)                  htobe16(x)
#define lwip_htonl(x)                  htobe32(x)
#define lwip_strnstr(buffer, token, n) strnstr(buffer, token, n)
#define lwip_stricmp(str1, str2)       strcasecmp(str1, str2)
#define lwip_strnicmp(str1, str2, len) strncasecmp(str1, str2, len)
#define lwip_itoa(buf, sz, num)        snprintf(buf, sz, "%d", num)

#define LWIP_PLATFORM_ASSERT(x)                                       \
    do {                                                              \
        fprintf(stderr, "Assertion \"%s\" failed at line %d in %s\n", \
                        x, __LINE__, __FILE_NAME__);                  \
        abort();                                                      \
    } while(0)
