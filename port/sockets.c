/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - BSD sockets server
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <sys/ioctl.h>

#define ifreq lwip_ifreq
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netif.h>
#include <lwip/netifapi.h>
#include <lwip/dhcp.h>
#include <lwip/prot/dhcp.h>
#undef ifreq
#undef IFNAMSIZ

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/sockport.h>

/* The system's AF_INET6 (<sys/socket.h>), which lwip/sockets.h redefines to AF_UNSPEC without IPv6 */
#define PHX_AF_INET6 10
#include <sys/sockios.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_arp.h>
#include <sys/threads.h>
#include <posix/utils.h>
#include <ifaddrs.h>

#if LWIP_IPV6
#include <net/if6.h>
#endif

#include "netif.h"
#include "route.h"
#include "ipsec-api.h"

#define SOCKTHREAD_PRIO    4
#define SOCKTHREAD_STACKSZ (4 * _PAGE_SIZE)

/* Idle workers kept for requests that wait (see "Socket servers" below) */
#define SOCKWORKER_IDLE_MAX 4


/* One socket's server: its port, its lwIP socket and the requests it has
 * handed to workers */
struct sock_srv {
	uint32_t port;
	int sock;
	pthread_mutex_t lock;
	pthread_cond_t idle;   /* signalled when inflight drops to 0 or a direction is released */
	unsigned int inflight; /* requests handed to workers, not yet answered */
	int busy[2];           /* a recv (SOCK_RX) / a send (SOCK_TX) is under way; under lock */
};

#define SOCK_RX 0
#define SOCK_TX 1


/* A request handed to a worker */
struct sock_job {
	struct sock_job *next;
	struct sock_srv *ss;
	msg_rid_t rid;
	ssize_t sent; /* a send: bytes the server thread has already sent, holding SOCK_TX for the rest */
	msg_t msg;    /* as received: not yet touched by socket_op() */
};


struct poll_state {
	int socket;
	fd_set rd, wr, ex;
};


static int wrap_socket(uint32_t *port, int sock, int flags);


#if LWIP_IPSEC
static int wrap_key_socket(uint32_t *port, int sock, int flags);
#endif /* LWIP_IPSEC */


static ssize_t map_errno(ssize_t ret)
{
	return ret < 0 ? -errno : ret;
}


// oh crap, there is no lwip_poll() ...
static int poll_one(struct poll_state *p, int events, time_t timeout)
{
	struct timeval to;
	int err;

	if (events & POLLIN)
		FD_SET(p->socket, &p->rd);
	else
		FD_CLR(p->socket, &p->rd);
	if (events & POLLOUT)
		FD_SET(p->socket, &p->wr);
	else
		FD_CLR(p->socket, &p->wr);
	if (events & POLLPRI)
		FD_SET(p->socket, &p->ex);
	else
		FD_CLR(p->socket, &p->ex);

	to.tv_sec = timeout / 1000000;
	to.tv_usec = timeout % 1000000;

	if ((err = lwip_select(p->socket + 1, &p->rd, &p->wr, &p->ex, timeout >= 0 ? &to : NULL)) <= 0)
		return err ? -errno : 0;

	events = 0;
	if (FD_ISSET(p->socket, &p->rd))
		events |= POLLIN;
	if (FD_ISSET(p->socket, &p->wr))
		events |= POLLOUT;
	if (FD_ISSET(p->socket, &p->ex))
		events |= POLLPRI;

	return events;
}


static const struct sockaddr *sa_convert_lwip_to_sys(const void *sa)
{
	// hack warning
	*(uint16_t *)sa = ((uint8_t *)sa)[1];
	return sa;
}


static const struct sockaddr *sa_convert_sys_to_lwip(const void *sa, socklen_t salen)
{
	uint16_t fam = *(volatile uint16_t *)sa;
	struct sockaddr *lsa = (void *)sa;

	if (fam != AF_PACKET) {
		lsa->sa_len = (uint8_t)salen;
		lsa->sa_family = (sa_family_t)fam;
	}

	return lsa;
}

#if LWIP_IPV6

/*
 * For IPv6 addresses we don't have any equivalent field,
 * to IPv4 netif->flags, so we need to generate them.
 */
static int netif_ip6_flags(struct netif *netif, unsigned int idx)
{
	int flags = 0;
	int state = netif_ip6_addr_state(netif, idx);

	if (ip6_addr_istentative(state)) {
		flags |= IN6_IFF_TENTATIVE;
	}

	if (ip6_addr_isduplicated(state)) {
		flags |= IN6_IFF_DUPLICATED;
	}

	if (ip6_addr_isdeprecated(state)) {
		flags |= IN6_IFF_DEPRECATED;
	}

	if (ip6_addr_isvalid(state) && !ip6_addr_ispreferred(state)) {
		flags |= IN6_IFF_DETACHED;
	}

	return flags;
}

/*
 * Generate IPv6 netmask.
 * For now lwip assumes all IPv6 address
 * are 64 bits long except for loopback address.
 */
static void inet6_addr_netmask_from_ip6addr(struct in6_addr *dst, const ip6_addr_t *src)
{
	memset(dst, 0xff, sizeof(*dst));
	if (!ip6_addr_isloopback(src)) {
		dst->un.u32_addr[2] = 0;
		dst->un.u32_addr[3] = 0;
	}
}

static int socket_ioctl6(int sock, unsigned long request, const void *in_data, void *out_data)
{
	switch (request) {
		case SIOCGIFNETMASK_IN6:
		case SIOCGIFAFLAG_IN6:
		case SIOCGIFALIFETIME_IN6: {
			struct in6_ifreq *in6_ifreq = (struct in6_ifreq *)out_data;
			struct netif *netif = netif_find(in6_ifreq->ifr_name);
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&in6_ifreq->ifr_addr;
			ip6_addr_t ip6addr;
			s8_t idx;
			u8_t uidx;
			int *flags;
			struct in6_addrlifetime *lifetime;

			if (netif == NULL) {
				return -ENXIO;
			}

			sin6 = (struct sockaddr_in6 *)sa_convert_sys_to_lwip(sin6, sizeof(struct sockaddr_in6));
			if (sin6->sin6_family != AF_INET6) {
				return -EINVAL;
			}

			inet6_addr_to_ip6addr(&ip6addr, &sin6->sin6_addr);
			idx = netif_get_ip6_addr_match(netif, &ip6addr);
			if (idx < 0) {
				return -ENXIO;
			}
			uidx = (u8_t)idx;

			switch (request) {
				case SIOCGIFNETMASK_IN6:
					inet6_addr_netmask_from_ip6addr(&sin6->sin6_addr, &ip6addr);
					break;
				case SIOCGIFAFLAG_IN6:
					flags = &in6_ifreq->ifr_ifru.ifru_flags6;
					*flags = netif_ip6_flags(netif, uidx);
					break;
				case SIOCGIFALIFETIME_IN6:
					lifetime = (struct in6_addrlifetime *)&in6_ifreq->ifr_ifru.ifru_lifetime;
					lifetime->preferred = netif_ip6_addr_pref_life(netif, uidx);
					lifetime->expire = netif_ip6_addr_valid_life(netif, uidx);
					break;
			}
			return EOK;
		}
		case SIOCDIFADDR_IN6: {
			struct in6_ifreq *in6_ifreq = (struct in6_ifreq *)in_data;
			struct netif *netif = netif_find(in6_ifreq->ifr_name);
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&in6_ifreq->ifr_addr;
			ip6_addr_t ip6addr;
			s8_t idx;

			if (netif == NULL) {
				return -ENXIO;
			}

			sin6 = (struct sockaddr_in6 *)sa_convert_sys_to_lwip(sin6, sizeof(struct sockaddr_in6));
			if (sin6->sin6_family != AF_INET6) {
				return -EINVAL;
			}

			inet6_addr_to_ip6addr(&ip6addr, &sin6->sin6_addr);
			idx = netif_get_ip6_addr_match(netif, &ip6addr);
			if (idx < 0) {
				return -ENXIO;
			}
			/* Remove address */
			netif_ip6_addr_set_state(netif, idx, IP6_ADDR_INVALID);
			netif_ip6_addr_set(netif, idx, IP6_ADDR_ANY6);

			return EOK;
		}
		case SIOCAIFADDR_IN6: {
			struct in6_aliasreq *in6_ifreq = (struct in6_aliasreq *)in_data;
			struct netif *netif = netif_find(in6_ifreq->ifra_name);
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&in6_ifreq->ifrau_addr;
			ip6_addr_t ip6addr;
			s8_t idx;
			u8_t uidx;

			if (netif == NULL) {
				return -ENXIO;
			}

			sin6 = (struct sockaddr_in6 *)sa_convert_sys_to_lwip(sin6, sizeof(struct sockaddr_in6));
			if (sin6->sin6_family != AF_INET6) {
				return -EINVAL;
			}

			inet6_addr_to_ip6addr(&ip6addr, &sin6->sin6_addr);
			idx = netif_get_ip6_addr_match(netif, &ip6addr);
			if (idx < 0) {
				if (netif_add_ip6_address(netif, &ip6addr, &idx) != ERR_OK) {
					return -ENOMEM;
				}
			}

			uidx = (u8_t)idx;

			netif_ip6_addr_set_pref_life(netif, uidx, in6_ifreq->ifra_lifetime.preferred);
			netif_ip6_addr_set_valid_life(netif, uidx, in6_ifreq->ifra_lifetime.expire);
			/* Ignore flags and netmask */

			return EOK;
		}
	}

	return -EAFNOSUPPORT;
}
#endif /* LWIP_IPV6 */

static int socket_ioctl(int sock, unsigned long request, const void *in_data, void *out_data)
{

#if 0
	printf("ioctl(type=0x%02x, cmd=0x%02x, size=%u, dev=%s)\n", (uint8_t)(request >> 8) & 0xFF, (uint8_t)request & 0xFF,
			IOCPARM_LEN(request), ((struct ifreq *) out_data)->ifr_name);
#endif
	switch (request) {
		case FIONREAD:
			/* read-only ioctl: the byte count is written back through out_data. */
			return map_errno(lwip_ioctl(sock, request, out_data));

		case FIONBIO:
			/* write-only ioctl: the on/off flag arrives in in_data. out_data is
			 * NULL for a write-only request (see ioctl_unpackEx: response_buf is
			 * only populated when IOC_OUT is set), so passing out_data here made
			 * lwip_ioctl read a zero flag and leave the socket blocking -- FIONBIO
			 * could never enable non-blocking mode. Pass the actual flag. */
			return map_errno(lwip_ioctl(sock, request, (void *)in_data));

		case SIOCGIFNAME: {
			struct ifreq *ifreq = (struct ifreq *)out_data;
			char *res;

			LWIP_ASSERT("IFNAMSIZ >= NETIF_NAMESIZE", IFNAMSIZ >= NETIF_NAMESIZE);
			res = netif_index_to_name(ifreq->ifr_ifindex, ifreq->ifr_name);
			if (res == NULL)
				return -ENXIO;

			return EOK;
		}

		case SIOCGIFINDEX: {
			struct ifreq *ifreq = (struct ifreq *)out_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			ifreq->ifr_ifindex = netif_get_index(interface);

			return EOK;
		}

		case SIOCGIFFLAGS: {
			/*
			These flags are not supported yet:
			IFF_DEBUG         Internal debugging flag.
			IFF_RUNNING       Resources allocated.
			IFF_NOARP         No arp protocol, L2 destination address not set.
			IFF_PROMISC       Interface is in promiscuous mode.
			IFF_NOTRAILERS    Avoid use of trailers.
			IFF_ALLMULTI      Receive all multicast packets.
			IFF_MASTER        Master of a load balancing bundle.
			IFF_SLAVE         Slave of a load balancing bundle.
			IFF_PORTSEL       Is able to select media type via ifmap.
			IFF_AUTOMEDIA     Auto media selection active.
			IFF_DYNAMIC       The addresses are lost when the interface goes down.
			IFF_LOWER_UP      Driver signals L1 up (since Linux 2.6.17)
			IFF_DORMANT       Driver signals dormant (since Linux 2.6.17)
			IFF_ECHO          Echo sent packets (since Linux 2.6.25)
			*/

			struct ifreq *ifreq = (struct ifreq *)out_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			ifreq->ifr_flags = 0;
			ifreq->ifr_flags |= netif_is_up(interface) ? IFF_UP : 0;
			ifreq->ifr_flags |= netif_is_link_up(interface) ? IFF_RUNNING : 0;
			ifreq->ifr_flags |= ip_addr_isloopback(&interface->ip_addr) ? IFF_LOOPBACK : 0;
			ifreq->ifr_flags |= (interface->flags & NETIF_FLAG_IGMP) ? IFF_MULTICAST : 0;
			if (netif_is_ppp(interface) || netif_is_tun(interface)) {
				ifreq->ifr_flags |= IFF_POINTOPOINT;
			}
			else {
				ifreq->ifr_flags |= IFF_BROADCAST;
			}

#if LWIP_DHCP
			if (netif_is_dhcp(interface))
				ifreq->ifr_flags |= IFF_DYNAMIC;
#endif
			return EOK;
		}
		case SIOCSIFFLAGS: {
			struct ifreq *ifreq = (struct ifreq *)in_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			// only IFF_UP flag supported
			if ((ifreq->ifr_flags & IFF_UP) && !netif_is_up(interface)) {
				netif_set_up(interface);
#if LWIP_DHCP
				if (netif_is_dhcp(interface))
					netifapi_dhcp_start(interface);
#endif
			}
			if (!(ifreq->ifr_flags & IFF_UP) && netif_is_up(interface)) {
#if LWIP_DHCP
				if (netif_is_dhcp(interface))
					netifapi_dhcp_release(interface);
#endif
				netif_set_down(interface);
			}

#if LWIP_DHCP
			if (!netif_is_ppp(interface) && !netif_is_tun(interface)) {
				/* can't start dhcp when interface is down and since we do not keep
				 * any information about dynamic flag it is not possible to 'set' interface
				 * as dynamic when it is downfc */
				if (netif_is_up(interface) && (ifreq->ifr_flags & IFF_DYNAMIC) && !netif_is_dhcp(interface))
					netifapi_dhcp_start(interface);

				if (!(ifreq->ifr_flags & IFF_DYNAMIC) && netif_is_dhcp(interface)) {
					netifapi_dhcp_release(interface);
					netifapi_dhcp_stop(interface);
				}
			}
#endif
			return EOK;
		}

		case SIOCGIFADDR:
		case SIOCGIFNETMASK:
		case SIOCGIFBRDADDR:
		case SIOCGIFDSTADDR: {
			struct ifreq *ifreq = (struct ifreq *)out_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			struct sockaddr_in *sin = NULL;
			switch (request) {
				case SIOCGIFADDR:
					sin = (struct sockaddr_in *)&ifreq->ifr_addr;
					inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_addr(interface));
					break;
				case SIOCGIFNETMASK:
					sin = (struct sockaddr_in *)&ifreq->ifr_netmask;
					inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_netmask(interface));
					break;
				case SIOCGIFBRDADDR:
					if (!netif_is_ppp(interface)) {
						sin = (struct sockaddr_in *)&ifreq->ifr_broadaddr;
						sin->sin_addr.s_addr = ip4_addr_get_u32(netif_ip4_addr(interface)) |
							~ip4_addr_get_u32(netif_ip4_netmask(interface));
					}
					else {
						return -EOPNOTSUPP;
					}
					break;
				case SIOCGIFDSTADDR:
					if (netif_is_ppp(interface) || netif_is_tun(interface)) {
						sin = (struct sockaddr_in *)&ifreq->ifr_dstaddr;
						inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_gw(interface));
					}
					else {
						return -EOPNOTSUPP;
					}
					break;
			}

			return EOK;
		}

		case SIOCSIFADDR:
		case SIOCSIFNETMASK:
		case SIOCSIFBRDADDR:
		case SIOCSIFDSTADDR: {
			struct ifreq *ifreq = (struct ifreq *)in_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			ip4_addr_t ip4addr;
			if (interface == NULL)
				return -ENXIO;

			struct sockaddr_in *sin;
			switch (request) {
				case SIOCSIFADDR:
					sin = (struct sockaddr_in *)&ifreq->ifr_addr;
					inet_addr_to_ip4addr(&ip4addr, &sin->sin_addr);
					netif_set_ipaddr(interface, &ip4addr);
					break;
				case SIOCSIFNETMASK:
					sin = (struct sockaddr_in *)&ifreq->ifr_netmask;
					inet_addr_to_ip4addr(&ip4addr, &sin->sin_addr);
					netif_set_netmask(interface, &ip4addr);
					break;
				case SIOCSIFBRDADDR:
					return -EOPNOTSUPP;
				case SIOCSIFDSTADDR:
					if (netif_is_tun(interface)) {
						sin = (struct sockaddr_in *)&ifreq->ifr_dstaddr;
						inet_addr_to_ip4addr(&ip4addr, &sin->sin_addr);
						netif_set_gw(interface, &ip4addr);
						break;
					}
					return -EOPNOTSUPP;
			}

#if LWIP_DHCP
			netifapi_dhcp_inform(interface);
#endif
			return EOK;
		}

		case SIOCGIFHWADDR: {
			struct ifreq *ifreq = (struct ifreq *)out_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			if (ip_addr_isloopback(&interface->ip_addr)) {
				ifreq->ifr_hwaddr.sa_family = ARPHRD_LOOPBACK;
			}
			else if (netif_is_ppp(interface)) {
				ifreq->ifr_hwaddr.sa_family = ARPHRD_PPP;
			}
			else if (netif_is_tun(interface)) {
				/* encap: UNSPEC that's what we want */
				ifreq->ifr_hwaddr.sa_family = -1;
			}
			else {
				ifreq->ifr_hwaddr.sa_family = ARPHRD_ETHER;
				ifreq->ifr_hwaddr.sa_len = interface->hwaddr_len;
				memcpy(ifreq->ifr_hwaddr.sa_data, interface->hwaddr, interface->hwaddr_len);
			}

			sa_convert_lwip_to_sys(&ifreq->ifr_hwaddr);
			return EOK;
		}

		case SIOCSIFHWADDR: {
			struct ifreq *ifreq = (struct ifreq *)in_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			/* TODO: support changing HW address */
			return -EOPNOTSUPP;
		}

#if 0

	case SIOCADDMULTI:
	case SIOCDELMULTI: {
		struct ifreq *ifreq = (struct ifreq *) arg;
		struct netif *interface = netif_find(ifreq->ifr_name);
		ip_addr_t group_ip;
		group_ip.addr = net_multicastMacToIp(ifreq->ifr_hwaddr.sa_data);
		group_ip.addr = lwip_ntohl(group_ip.addr);

		if (cmd == SIOCADDMULTI)
			igmp_joingroup(&interface->ip_addr, &group_ip);
		else
			igmp_leavegroup(&interface->ip_addr, &group_ip);

		return EOK;
	}
#endif
		case SIOCGIFMTU: {
			struct ifreq *ifreq = (struct ifreq *)out_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			ifreq->ifr_mtu = interface->mtu;
			return EOK;
		}
		case SIOCSIFMTU: {
			struct ifreq *ifreq = (struct ifreq *)in_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			// TODO: check MAC constraints
			if (ifreq->ifr_mtu < 64 || ifreq->ifr_mtu > 32768)
				return -EINVAL;

			interface->mtu = ifreq->ifr_mtu;
			return EOK;
		}
		case SIOCGIFMETRIC: {
			struct ifreq *ifreq = (struct ifreq *)out_data;
			struct netif *interface = netif_find(ifreq->ifr_name);
			if (interface == NULL)
				return -ENXIO;

			ifreq->ifr_metric = 0;
			return EOK;
		}
		case SIOCSIFMETRIC:
			return -EOPNOTSUPP;

		case SIOCGIFTXQLEN:
			return -EOPNOTSUPP;

		case SIOCSIFTXQLEN:
			return -EOPNOTSUPP;

		case SIOCGIFCONF: {
			struct ifconf *ifconf = out_data;
			struct ifreq *ifreq = NULL;
			struct netif *netif;
			const int maxlen = (ifconf->ifc_buf != NULL) ? ifconf->ifc_len : 0;

			if (maxlen != 0) {
				int err = IOC_NESTED_GET_PTR_FIELD(request, (void **)&ifreq, ifconf, ifc_req);
				if (err < 0) {
					return err;
				}
			}

			ifconf->ifc_len = 0;

			for (netif = netif_list; netif != NULL; netif = netif->next) {
				if (maxlen != 0 && ifconf->ifc_len + sizeof(struct ifreq) > maxlen) {
					break;
				}

				if (ifreq != NULL) {
					/* LWiP name is only 2 chars, we have to manually add the number */
					snprintf(ifreq->ifr_name, IFNAMSIZ, "%c%c%d", netif->name[0], netif->name[1], netif->num);

					struct sockaddr_in *sin = (struct sockaddr_in *)&ifreq->ifr_addr;
					inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_addr(netif));

					ifreq += 1;
				}

				ifconf->ifc_len += sizeof(struct ifreq);
			}

			return EOK;
		}

		/** ROUTING
		 * net and host routing is supported and multiple gateways with ethernet interfaces
		 * TODO: support metric
		 */
		case SIOCADDRT:
		case SIOCDELRT: {
			struct rtentry *rt = (struct rtentry *)in_data;
			if (rt == NULL) {
				return -EFAULT;
			}

			char *rt_dev;
			int err = IOC_NESTED_GET_PTR_FIELD(request, (void **)&rt_dev, rt, rt_dev);
			if (err < 0) {
				return err;
			}
			if (rt_dev == NULL) {
				return -EINVAL;
			}

			struct netif *interface = netif_find(rt_dev);
			int ret = EOK;
			if (interface == NULL) {
				return -ENXIO;
			}

			switch (request) {
				case SIOCADDRT:
					ret = route_add(interface, rt);
					break;

				case SIOCDELRT:
					ret = route_del(interface, rt);
					break;

				default:
					break;
			}

			return ret;
		}

#if LWIP_IPV6
		case SIOCGIFDSTADDR_IN6:
		case SIOCGIFNETMASK_IN6:
		case SIOCDIFADDR_IN6:
		case SIOCAIFADDR_IN6:
		case SIOCGIFAFLAG_IN6:
		case SIOCGIFALIFETIME_IN6:
			return socket_ioctl6(sock, request, in_data, out_data);
#endif /* LWIP IPV6 */
	}

	return -EINVAL;
}


static void do_socket_ioctl(msg_t *msg, int sock)
{
	unsigned long request;
	void *out_data = NULL;
	const void *in_data = ioctl_unpackEx(msg, &request, NULL, &out_data);

	msg->o.err = socket_ioctl(sock, request, in_data, out_data);
}


/* xflags: MSG_* flags added to a recv or send (MSG_DONTWAIT for a try that must not wait) */
static int socket_op(msg_t *msg, int sock, int xflags)
{
	const sockport_msg_t *smi = (const void *)msg->i.raw;
	sockport_resp_t *smo = (void *)msg->o.raw;
	struct poll_state polls = { 0 };
	uint32_t new_port;
	socklen_t salen;
	int err;

	polls.socket = sock;
	salen = sizeof(smo->sockname.addr);

#if LWIP_IPSEC
	if (is_key_sockets_fd(sock)) {
		switch (msg->type) {
			case sockmSend:
				smo->ret = map_errno(key_sockets_send(sock, msg->i.data, msg->i.size, smi->send.flags));
				break;
			case sockmRecv:
				smo->ret = map_errno(key_sockets_recv(sock, msg->o.data, msg->o.size, smi->send.flags));
				break;
			case sockmGetOpt:
				smo->ret = -EINVAL;
				break;
			case sockmSetOpt:
				smo->ret = -EINVAL;
				break;
			case mtRead:
				msg->o.err = map_errno(key_sockets_recv(sock, msg->o.data, msg->o.size, 0));
				break;
			case mtWrite:
				msg->o.err = map_errno(key_sockets_send(sock, msg->i.data, msg->i.size, 0));
				break;
			case mtGetAttr:
				if (msg->i.attr.type != atPollStatus) {
					msg->o.err = -EINVAL;
					break;
				}
				msg->o.attr.val = key_sockets_poll(sock, msg->i.attr.val, 0);
				msg->o.err = (msg->o.attr.val < 0) ? msg->o.attr.val : EOK;
				break;
			case mtClose:
				msg->o.err = map_errno(key_sockets_close(sock));
				return 1;
			case sockmGetSockName:
				smo->ret = -EINVAL;
				break;
			default:
				smo->ret = -EINVAL;
				break;
		}

		return 0;
	}
#endif /* LWIP_IPSEC */

	switch (msg->type) {
		case sockmConnect:
			smo->ret = map_errno(lwip_connect(sock, sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen));
			break;
		case sockmBind:
			smo->ret = map_errno(lwip_bind(sock, sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen));
			break;
		case sockmListen:
			smo->ret = map_errno(lwip_listen(sock, smi->listen.backlog));
			break;
		case sockmAccept:
			err = lwip_accept(sock, (void *)smo->sockname.addr, &salen);
			if (err >= 0) {
				sa_convert_lwip_to_sys(smo->sockname.addr);
				smo->sockname.addrlen = salen;
				err = wrap_socket(&new_port, err, smi->send.flags);
				smo->ret = err < 0 ? err : new_port;
			}
			else {
				smo->ret = -errno;
			}
			break;
		case sockmSend:
			smo->ret = map_errno(lwip_sendto(sock, msg->i.data, msg->i.size, smi->send.flags | xflags,
				smi->send.addrlen == 0 ? NULL : sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen));
			break;
		case sockmRecv:
			smo->ret = map_errno(lwip_recvfrom(sock, msg->o.data, msg->o.size, smi->send.flags | xflags, (void *)smo->sockname.addr, &salen));
			if (smo->ret >= 0)
				sa_convert_lwip_to_sys(smo->sockname.addr);
			smo->sockname.addrlen = salen;
			break;
		case sockmGetSockName:
			smo->ret = map_errno(lwip_getsockname(sock, (void *)smo->sockname.addr, &salen));
			if (smo->ret >= 0)
				sa_convert_lwip_to_sys(smo->sockname.addr);
			smo->sockname.addrlen = salen;
			break;
		case sockmGetPeerName:
			smo->ret = map_errno(lwip_getpeername(sock, (void *)smo->sockname.addr, &salen));
			if (smo->ret >= 0)
				sa_convert_lwip_to_sys(smo->sockname.addr);
			smo->sockname.addrlen = salen;
			break;
		case sockmGetFl:
			smo->ret = map_errno(lwip_fcntl(sock, F_GETFL, 0));
			break;
		case sockmSetFl:
			smo->ret = map_errno(lwip_fcntl(sock, F_SETFL, smi->send.flags));
			break;
		case sockmGetOpt:
			if (smi->opt.optname == IP_IPSEC_POLICY) {
				/* TODO: IP_IPSEC_POLICY */
				smo->ret = 0;
				break;
			}
			salen = msg->o.size;
			smo->ret = lwip_getsockopt(sock, smi->opt.level, smi->opt.optname, msg->o.data, &salen) < 0 ? -errno : salen;
			break;
		case sockmSetOpt:
			if (smi->opt.optname == IP_IPSEC_POLICY) {
				/* TODO: IP_IPSEC_POLICY */
				smo->ret = 0;
				break;
			}
			smo->ret = map_errno(lwip_setsockopt(sock, smi->opt.level, smi->opt.optname, msg->i.data, msg->i.size));
			break;
		case sockmShutdown:
			smo->ret = map_errno(lwip_shutdown(sock, smi->send.flags));
			break;
		case mtRead:
			if (msg->o.size <= SSIZE_MAX)
				msg->o.err = map_errno(lwip_recvfrom(sock, msg->o.data, msg->o.size, xflags, NULL, NULL));
			else
				msg->o.err = -EINVAL;
			break;
		case mtWrite:
			if (msg->i.size <= SSIZE_MAX)
				msg->o.err = map_errno(lwip_sendto(sock, msg->i.data, msg->i.size, xflags, NULL, 0));
			else
				msg->o.err = -EINVAL;
			break;
		case mtGetAttr:
			if (msg->i.attr.type != atPollStatus) {
				msg->o.err = -EINVAL;
				break;
			}
			/* atPollStatus val: low 16 bits = poll event mask. The kernel's
			 * single-socket poll fast-path (posix_poll, ftInetSocket) may pack a
			 * block timeout (ms) in the high bits so this dedicated per-socket
			 * thread BLOCKS in lwip_select until the socket is ready (lwip wakes on
			 * the netconn callback) instead of the kernel spin-polling every
			 * POLL_INTERVAL. High bits 0 => timeout 0 => the legacy instantaneous
			 * snapshot, so every other caller (multi-fd poll, non-inet fds) is
			 * unchanged. Blocking here only stalls THIS socket's own thread. */
			{
				long long v = msg->i.attr.val;
				int pollev = (int)(v & 0xFFFFLL);
				time_t block_us = (time_t)(((unsigned long long)v >> 16) * 1000ULL);
				msg->o.attr.val = poll_one(&polls, pollev, block_us);
			}
			msg->o.err = (msg->o.attr.val < 0) ? msg->o.attr.val : EOK;
			break;
		case mtClose:
			msg->o.err = map_errno(lwip_close(sock));
			return 1;
		case mtDevCtl:
			do_socket_ioctl(msg, sock);
			break;
		default:
			smo->ret = -EINVAL;
			break;
	}

	return 0;
}


/*
 * Socket servers
 *
 * Every socket has a port and a server thread that receives its requests. A
 * request that waits -- a blocking accept, connect, recv or send, or a poll that
 * waits for readiness -- must not hold up the socket's other requests: the
 * thread that would make it ready may need one of them first. CPython's
 * `c.connect(s.getsockname())`, while another thread waits in `s.accept()`, sent
 * getsockname() to the listener's server thread, which was inside lwip_accept()
 * waiting for that very connect: both threads hung.
 *
 * So the server thread answers at once whatever cannot wait, tries a recv, a
 * send or a poll without waiting first, and hands only what must wait to a
 * worker -- a thread from a pool shared by all sockets -- which answers it when
 * lwIP returns. Data that is already there costs no hand-off.
 *
 * lwIP (without LWIP_NETCONN_FULLDUPLEX) takes one receiver and one sender on a
 * socket at a time, so recvs take turns (SOCK_RX), and so do sends (SOCK_TX). Closing
 * needs no lock: the kernel holds a reference to the file across every request
 * it sends, so mtClose comes only after all of them have been answered. The
 * server still waits for its workers to let go of the socket before closing.
 */

static struct {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct sock_job *head, *tail;
	unsigned int queued; /* jobs no worker has taken yet */
	unsigned int idle;   /* workers waiting for a job */
} sockpool;


/* Copies a request. The kernel packs a small mtRead/mtWrite payload into the
 * message itself (msg_opack(): o.data / i.data then point into o.raw / i.raw),
 * so those pointers must follow the copy -- or a worker reading into o.data
 * would fill the server thread's message, not the one it answers with. */
static void sock_msgCopy(msg_t *dst, const msg_t *src)
{
	const char *iraw = (const char *)src->i.raw, *oraw = (const char *)src->o.raw;
	const char *idata = src->i.data, *odata = src->o.data;

	*dst = *src;
	if ((idata >= iraw) && (idata < iraw + sizeof(src->i.raw))) {
		dst->i.data = (char *)dst->i.raw + (idata - iraw);
	}
	if ((odata >= oraw) && (odata < oraw + sizeof(src->o.raw))) {
		dst->o.data = (char *)dst->o.raw + (odata - oraw);
	}
}


static void sock_srvPut(struct sock_srv *ss)
{
	(void)pthread_mutex_lock(&ss->lock);
	if (--ss->inflight == 0U) {
		(void)pthread_cond_broadcast(&ss->idle);
	}
	(void)pthread_mutex_unlock(&ss->lock);
}


static void sock_srvWaitIdle(struct sock_srv *ss)
{
	(void)pthread_mutex_lock(&ss->lock);
	while (ss->inflight != 0U) {
		(void)pthread_cond_wait(&ss->idle, &ss->lock);
	}
	(void)pthread_mutex_unlock(&ss->lock);
}


/* SOCK_RX, SOCK_TX or -1: the direction a request moves data in */
static int sock_dir(int type)
{
	switch (type) {
		case sockmRecv:
		case mtRead:
			return SOCK_RX;
		case sockmSend:
		case mtWrite:
			return SOCK_TX;
		default:
			return -1;
	}
}


/* A direction is held by whichever thread runs the recv (send), not owned by
 * one: a split send takes it on the server thread and releases it on a worker */
static int sock_dirTake(struct sock_srv *ss, int dir, int wait)
{
	int taken = 0;

	(void)pthread_mutex_lock(&ss->lock);
	while ((ss->busy[dir] != 0) && (wait != 0)) {
		(void)pthread_cond_wait(&ss->idle, &ss->lock);
	}
	if (ss->busy[dir] == 0) {
		ss->busy[dir] = 1;
		taken = 1;
	}
	(void)pthread_mutex_unlock(&ss->lock);

	return taken;
}


static void sock_dirRelease(struct sock_srv *ss, int dir)
{
	(void)pthread_mutex_lock(&ss->lock);
	ss->busy[dir] = 0;
	(void)pthread_cond_broadcast(&ss->idle);
	(void)pthread_mutex_unlock(&ss->lock);
}


static void socket_setResult(msg_t *msg, ssize_t ret)
{
	sockport_resp_t *smo = (void *)msg->o.raw;

	if ((msg->type == sockmRecv) || (msg->type == sockmSend)) {
		smo->ret = ret;
	}
	else {
		msg->o.err = ret;
	}
}


/* The rest of a send the server thread has sent part of without waiting */
static void sockjob_sendRest(struct sock_job *job)
{
	msg_t *msg = &job->msg;
	const sockport_msg_t *smi = (const void *)msg->i.raw;
	const struct sockaddr *to = NULL;
	socklen_t tolen = 0;
	int flags = 0;
	ssize_t ret;

	if (msg->type == sockmSend) {
		flags = smi->send.flags;
		if (smi->send.addrlen != 0) {
			to = sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen);
			tolen = smi->send.addrlen;
		}
	}

	ret = lwip_sendto(job->ss->sock, (const char *)msg->i.data + job->sent, msg->i.size - job->sent, flags, to, tolen);
	/* An error after a partial send reports what was sent, as send() does */
	socket_setResult(msg, (ret < 0) ? job->sent : (job->sent + ret));
}


static void sockjob_run(struct sock_job *job)
{
	struct sock_srv *ss = job->ss;
	int dir = sock_dir(job->msg.type);

	if (job->sent > 0) {
		/* SOCK_TX came with the job: no other send may come between the two parts */
		sockjob_sendRest(job);
	}
	else {
		if (dir >= 0) {
			(void)sock_dirTake(ss, dir, 1);
		}
		(void)socket_op(&job->msg, ss->sock, 0);
	}
	if (dir >= 0) {
		sock_dirRelease(ss, dir);
	}

	msgRespond(ss->port, &job->msg, job->rid);
	sock_srvPut(ss);
}


/* Takes a queued job, if there is one, and runs it. Called with sockpool.lock
 * held; returns with it held. */
static int sockpool_runOne(void)
{
	struct sock_job *job = sockpool.head;

	if (job == NULL) {
		return 0;
	}

	sockpool.head = job->next;
	if (sockpool.head == NULL) {
		sockpool.tail = NULL;
	}
	sockpool.queued--;

	(void)pthread_mutex_unlock(&sockpool.lock);
	sockjob_run(job);
	free(job);
	(void)pthread_mutex_lock(&sockpool.lock);

	return 1;
}


static void sockworker_thread(void *arg)
{
	(void)arg;

	(void)pthread_mutex_lock(&sockpool.lock);
	for (;;) {
		if (sockpool_runOne() != 0) {
			continue;
		}
		if (sockpool.idle >= SOCKWORKER_IDLE_MAX) {
			break;
		}
		sockpool.idle++;
		(void)pthread_cond_wait(&sockpool.cond, &sockpool.lock);
		sockpool.idle--;
	}
	(void)pthread_mutex_unlock(&sockpool.lock);
}


/* Hands a request that has to wait to a worker, which answers it */
static void sockjob_submit(struct sock_srv *ss, const msg_t *msg, msg_rid_t rid, ssize_t sent)
{
	struct sock_job *job, local;
	int spawn;

	job = malloc(sizeof(*job));

	(void)pthread_mutex_lock(&ss->lock);
	ss->inflight++;
	(void)pthread_mutex_unlock(&ss->lock);

	if (job == NULL) {
		/* Answer it here, waiting, as before workers existed */
		local.ss = ss;
		local.rid = rid;
		local.sent = sent;
		sock_msgCopy(&local.msg, msg);
		sockjob_run(&local);
		return;
	}

	job->next = NULL;
	job->ss = ss;
	job->rid = rid;
	job->sent = sent;
	sock_msgCopy(&job->msg, msg);

	(void)pthread_mutex_lock(&sockpool.lock);
	if (sockpool.tail != NULL) {
		sockpool.tail->next = job;
	}
	else {
		sockpool.head = job;
	}
	sockpool.tail = job;
	sockpool.queued++;
	/* An idle worker takes it, unless each one already has a job coming */
	spawn = (sockpool.idle < sockpool.queued) ? 1 : 0;
	(void)pthread_cond_signal(&sockpool.cond);
	(void)pthread_mutex_unlock(&sockpool.lock);

	if ((spawn != 0) && (sys_thread_opt_new("sockworker", sockworker_thread, NULL, SOCKTHREAD_STACKSZ, SOCKTHREAD_PRIO, NULL) != 0)) {
		/* No thread for it: run a queued job here, so that every job is taken */
		(void)pthread_mutex_lock(&sockpool.lock);
		(void)sockpool_runOne();
		(void)pthread_mutex_unlock(&sockpool.lock);
	}
}


static int socket_isNonblocking(int sock)
{
	int fl = lwip_fcntl(sock, F_GETFL, 0);

	return ((fl >= 0) && ((fl & O_NONBLOCK) != 0)) ? 1 : 0;
}


static ssize_t socket_result(const msg_t *msg)
{
	const sockport_resp_t *smo = (const void *)msg->o.raw;

	return ((msg->type == sockmRecv) || (msg->type == sockmSend)) ? smo->ret : msg->o.err;
}


/* Serves a request on the server thread, answering it there or handing it to a
 * worker. Returns 1 if msg has been answered here (the caller responds). */
static int socket_serve(struct sock_srv *ss, msg_t *msg, msg_rid_t rid)
{
	const sockport_msg_t *smi = (const void *)msg->i.raw;
	long long pollval;
	int dir, dontwait;
	ssize_t ret;
	size_t size;
	msg_t orig;

#if LWIP_IPSEC
	if (is_key_sockets_fd(ss->sock)) {
		(void)socket_op(msg, ss->sock, 0);
		return 1;
	}
#endif /* LWIP_IPSEC */

	switch (msg->type) {
		case sockmAccept:
		case sockmConnect:
			if (socket_isNonblocking(ss->sock) == 0) {
				sockjob_submit(ss, msg, rid, 0);
				return 0;
			}
			break;

		case mtGetAttr:
			pollval = msg->i.attr.val;
			if ((msg->i.attr.type != atPollStatus) || ((pollval >> 16) == 0)) {
				break;
			}
			/* A poll that may wait for readiness: look without waiting first */
			sock_msgCopy(&orig, msg);
			msg->i.attr.val = pollval & 0xFFFFLL;
			(void)socket_op(msg, ss->sock, 0);
			if ((msg->o.err == EOK) && (msg->o.attr.val == 0)) {
				sockjob_submit(ss, &orig, rid, 0);
				return 0;
			}
			return 1;

		case sockmRecv:
		case mtRead:
		case sockmSend:
		case mtWrite:
			dir = sock_dir(msg->type);
			dontwait = ((msg->type == sockmRecv) || (msg->type == sockmSend)) && ((smi->send.flags & MSG_DONTWAIT) != 0);
			sock_msgCopy(&orig, msg);
			if (sock_dirTake(ss, dir, 0) == 0) {
				/* Another recv (send) is under way */
				if ((dontwait != 0) || (socket_isNonblocking(ss->sock) != 0)) {
					socket_setResult(msg, -EAGAIN);
					return 1;
				}
				/* Wait for it on a worker */
				sockjob_submit(ss, &orig, rid, 0);
				return 0;
			}
			(void)socket_op(msg, ss->sock, MSG_DONTWAIT);

			ret = socket_result(msg);
			size = ((msg->type == sockmSend) || (msg->type == mtWrite)) ? msg->i.size : 0;
			if (((ret != -EAGAIN) && (ret != -EWOULDBLOCK) && ((ret < 0) || (ret >= (ssize_t)size))) ||
					(dontwait != 0) || (socket_isNonblocking(ss->sock) != 0)) {
				/* Done (data or EOF received, all sent, an error), or the caller
				 * does not wait: this is the answer */
				sock_dirRelease(ss, dir);
				return 1;
			}
			if (ret <= 0) {
				/* Nothing moved: the worker starts afresh */
				sock_dirRelease(ss, dir);
				ret = 0;
			}
			/* else: part of a send went; the worker sends the rest still holding SOCK_TX */
			sockjob_submit(ss, &orig, rid, ret);
			return 0;

		default:
			break;
	}

	(void)socket_op(msg, ss->sock, 0);
	return 1;
}


static void socket_thread(void *arg)
{
	struct sock_srv *ss = arg;
	msg_rid_t respid;
	msg_t msg;
	int err, closed = 0;

	while ((err = msgRecv(ss->port, &msg, &respid)) >= 0) {
		if (msg.type == mtClose) {
			sock_srvWaitIdle(ss);
			closed = socket_op(&msg, ss->sock, 0);
			msgRespond(ss->port, &msg, respid);
			break;
		}
		if (socket_serve(ss, &msg, respid) != 0) {
			msgRespond(ss->port, &msg, respid);
		}
	}

	sock_srvWaitIdle(ss);
	portDestroy(ss->port);
	if (closed == 0) {
		lwip_close(ss->sock);
	}

	/* A worker's last touch of ss is its unlock of ss->lock in sock_srvPut(), and a
	 * pthread mutex unlock touches nothing of the mutex after releasing it */
	(void)pthread_cond_destroy(&ss->idle);
	(void)pthread_mutex_destroy(&ss->lock);
	free(ss);
}


/* Creates the server (port + thread) of an open socket; closes the socket on failure */
static int sock_srvStart(uint32_t *port, int sock, int (*closefn)(int))
{
	struct sock_srv *ss;
	int err;

	ss = calloc(1, sizeof(*ss));
	if (ss == NULL) {
		closefn(sock);
		return -ENOMEM;
	}

	ss->sock = sock;
	if (pthread_mutex_init(&ss->lock, NULL) != 0) {
		closefn(sock);
		free(ss);
		return -ENOMEM;
	}
	if (pthread_cond_init(&ss->idle, NULL) != 0) {
		(void)pthread_mutex_destroy(&ss->lock);
		closefn(sock);
		free(ss);
		return -ENOMEM;
	}

	if ((err = portCreate(&ss->port)) == 0) {
		*port = ss->port;
		err = sys_thread_opt_new("socket", socket_thread, ss, SOCKTHREAD_STACKSZ, SOCKTHREAD_PRIO, NULL);
		if (err == 0) {
			return EOK;
		}
		portDestroy(ss->port);
	}

	(void)pthread_cond_destroy(&ss->idle);
	(void)pthread_mutex_destroy(&ss->lock);
	closefn(sock);
	free(ss);
	return err;
}


static int wrap_socket(uint32_t *port, int sock, int flags)
{
	int err;

	if ((flags & SOCK_NONBLOCK) && (err = lwip_fcntl(sock, F_SETFL, O_NONBLOCK)) < 0) {
		lwip_close(sock);
		return err;
	}

	return sock_srvStart(port, sock, lwip_close);
}


#if LWIP_IPSEC
static int wrap_key_socket(uint32_t *port, int sock, int flags)
{
	/* no flags are supported by AF_KEY socket */
	return sock_srvStart(port, sock, key_sockets_close);
}
#endif /* LWIP_IPSEC */


static int do_getnameinfo(const struct sockaddr *sa, socklen_t addrlen, char *host, socklen_t hostsz, char *serv, socklen_t servsz, int flags)
{

	// TODO: implement real netdb (for now always return the IP representation)
	if (sa == NULL)
		return EAI_FAIL;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sa_in = (struct sockaddr_in *)sa;

		/* Guard on sz > 0: servsz/hostsz are unsigned, so `buf[sz - 1]` with
		 * sz == 0 wraps to buf[0xffffffff] -> an out-of-bounds write that faulted
		 * the whole lwip server (a caller may pass a non-NULL buffer with size 0,
		 * e.g. getnameinfo for only the host or only the service). snprintf already
		 * NUL-terminates within a non-zero buffer; the explicit terminator is just
		 * defensive and must not run when sz == 0. */
		if (host != NULL && hostsz > 0) {
			snprintf(host, hostsz, "%u.%u.%u.%u", (unsigned char)sa->sa_data[2], (unsigned char)sa->sa_data[3],
				(unsigned char)sa->sa_data[4], (unsigned char)sa->sa_data[5]);
			host[hostsz - 1] = '\0';
		}

		if (serv != NULL && servsz > 0) {
			snprintf(serv, servsz, "%u", ntohs(sa_in->sin_port));
			serv[servsz - 1] = '\0';
		}

		return 0;
	}

	return EAI_FAMILY;
}


#if LWIP_DNS
static int do_getaddrinfo(const char *name, const char *serv, const struct addrinfo *hints, void *buf, size_t *buflen)
{
	struct addrinfo *res, *ai, *dest;
	size_t n, addr_needed, str_needed;
	void *addrdest, *strdest;
	int err;

	if ((err = lwip_getaddrinfo(name, serv, hints, &res)))
		return err;

	n = addr_needed = str_needed = 0;
	for (ai = res; ai; ai = ai->ai_next) {
		++n;
		if (ai->ai_addrlen)
			addr_needed += (ai->ai_addrlen + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1);
		if (ai->ai_canonname)
			str_needed += strlen(ai->ai_canonname) + 1;
	}

	str_needed += n * sizeof(*ai) + addr_needed;
	if (*buflen < str_needed) {
		*buflen = str_needed;
		if (res)
			lwip_freeaddrinfo(res);
		return EAI_OVERFLOW;
	}

	*buflen = str_needed;
	dest = buf;
	addrdest = buf + n * sizeof(*ai);
	strdest = addrdest + addr_needed;

	for (ai = res; ai; ai = ai->ai_next) {
		dest->ai_flags = ai->ai_flags;
		dest->ai_family = ai->ai_family;
		dest->ai_socktype = ai->ai_socktype;
		dest->ai_protocol = ai->ai_protocol;

		if ((dest->ai_addrlen = ai->ai_addrlen)) {
			memcpy(addrdest, ai->ai_addr, ai->ai_addrlen);
			sa_convert_lwip_to_sys(addrdest);
			dest->ai_addr = (void *)(addrdest - buf);
			addrdest += (ai->ai_addrlen + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1);
		}

		if (ai->ai_canonname) {
			n = strlen(ai->ai_canonname) + 1;
			memcpy(strdest, ai->ai_canonname, n);
			dest->ai_canonname = (void *)(strdest - buf);
			strdest += n;
		}
		else {
			dest->ai_canonname = NULL;
		}

		dest->ai_next = ai->ai_next ? (void *)((void *)(dest + 1) - buf) : NULL;
		++dest;
	}

	if (res)
		lwip_freeaddrinfo(res);

	return 0;
}
#endif

static int do_getifaddrs(char *buf, size_t *buflen)
{
	struct sockaddr_storage sa;
	struct sockaddr_in *sin;
	struct ifaddrs *dest;
	struct netif *netif;
	char *addrdest, *strdest;
	size_t n_ifaddrs = 0, needed;
	size_t str_needed = 0, addr_needed = 0;
#if LWIP_IPV6
	struct sockaddr_in6 *sin6;
	int i;
#endif

	NETIF_FOREACH(netif) {
		n_ifaddrs++;
		/* lwip_netif_name | netif_num | '\0' */
		str_needed += sizeof(netif->name) + 2;
		/* IPv4 addr, netmask, gw/dsy */
		addr_needed += 3 * sizeof(struct sockaddr_in);
#if LWIP_IPV6
		/* Count IPv6 addresses */
		for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
			if (!ip6_addr_isinvalid(netif_ip6_addr_state(netif, i))) {
				n_ifaddrs++;
				addr_needed += 2 * sizeof(struct sockaddr_in6);
			}
		}
#endif /* LWIP_IPv6 */
	}

	needed = n_ifaddrs * sizeof(struct ifaddrs) + str_needed + addr_needed;
	if (needed > *buflen) {
		*buflen = needed;
		return EAI_OVERFLOW;
	}
	*buflen = needed;
	dest = (struct ifaddrs *)buf;
	addrdest = buf + n_ifaddrs * sizeof(*dest);
	strdest = addrdest + addr_needed;

	memset(buf, 0, needed);
	memset(&sa, 0, sizeof(sa));
	sin = (struct sockaddr_in *)&sa;
	NETIF_FOREACH(netif) {
		dest->ifa_flags = netif->flags;
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(struct sockaddr_in);

		inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_addr(netif));
		memcpy(addrdest, sin, sin->sin_len);
		dest->ifa_addr = (struct sockaddr *)(addrdest - buf);
		addrdest += sizeof(struct sockaddr_in);

		inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_gw(netif));
		memcpy(addrdest, sin, sin->sin_len);
		dest->ifa_dstaddr = (struct sockaddr *)(addrdest - buf);
		addrdest += sizeof(struct sockaddr_in);

		inet_addr_from_ip4addr(&sin->sin_addr, netif_ip4_netmask(netif));
		memcpy(addrdest, sin, sin->sin_len);
		dest->ifa_netmask = (struct sockaddr *)(addrdest - buf);
		addrdest += sizeof(struct sockaddr_in);

		snprintf(strdest, sizeof(netif->name) + 2, "%.2s%1u", netif->name, netif->num % 10);
		dest->ifa_name = (char *)(strdest - buf);
#if LWIP_IPV6
		sin6 = (struct sockaddr_in6 *)&sa;
		for (i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
			if (!ip6_addr_isinvalid(netif_ip6_addr_state(netif, i))) {
				dest->ifa_next = (struct ifaddrs *)((char *)(dest + 1) - buf);
				++dest;
				sin6->sin6_family = AF_INET6;
				sin6->sin6_len = sizeof(struct sockaddr_in6);
				sin6->sin6_scope_id = ip6_addr_zone(netif_ip6_addr(netif, i));
				inet6_addr_from_ip6addr(&sin6->sin6_addr, netif_ip6_addr(netif, i));
				memcpy(addrdest, sin6, sin6->sin6_len);
				dest->ifa_addr = (struct sockaddr *)(addrdest - buf);
				addrdest += sizeof(struct sockaddr_in6);

				sin6->sin6_scope_id = 0;
				inet6_addr_netmask_from_ip6addr(&sin6->sin6_addr, netif_ip6_addr(netif, i));
				memcpy(addrdest, sin6, sin6->sin6_len);
				dest->ifa_netmask = (struct sockaddr *)(addrdest - buf);
				addrdest += sizeof(struct sockaddr_in6);

				dest->ifa_name = (char *)(strdest - buf);
				dest->ifa_flags = netif_ip6_flags(netif, i);
			}
		}
#endif /* LWIP_IPV6 */
		strdest += sizeof(netif->name) + 2;
		dest->ifa_next = netif->next ? (struct ifaddrs *)((char *)(dest + 1) - buf) : NULL;
		++dest;
	}

	return 0;
}

static void socketsrv_thread(void *arg)
{
	msg_rid_t respid;
	size_t sz;
	msg_t msg;
	uint32_t port;
	int err, sock, type;
#if LWIP_DNS
	struct addrinfo hint = { 0 };
	const char *node, *serv;
#endif

	port = (uintptr_t)arg;

	while ((err = msgRecv(port, &msg, &respid)) >= 0) {
		const sockport_msg_t *smi = (const void *)msg.i.raw;
		sockport_resp_t *smo = (void *)msg.o.raw;

		switch (msg.type) {
			case sockmSocket:
				type = smi->socket.type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
				if (smi->socket.domain == AF_KEY) {
#if LWIP_IPSEC
					if ((sock = key_sockets_socket(smi->socket.domain, type, smi->socket.protocol)) < 0) {
						msg.o.err = -errno;
					}
					else {
						msg.o.err = wrap_key_socket(&msg.o.lookup.dev.port, sock, smi->socket.type);
						msg.o.lookup.fil = msg.o.lookup.dev;
					}
#else
					msg.o.err = -EINVAL;
#endif /* LWIP_IPSEC */
					break;
				}
#if !LWIP_IPV6
				/* Without IPv6, lwip_socket() ignores the domain and returns an
				 * IPv4 socket, on which the caller's first sockaddr_in6 fails
				 * with EIO. Refuse it here so it can fall back to AF_INET.
				 * The domain is the system's value (<sys/socket.h>, 10): lwip's own
				 * AF_INET6 is AF_UNSPEC (0) when it is built without IPv6. */
				if (smi->socket.domain == PHX_AF_INET6) {
					msg.o.err = -EAFNOSUPPORT;
					break;
				}
#endif
				if ((sock = lwip_socket(smi->socket.domain, type, smi->socket.protocol)) < 0)
					msg.o.err = -errno;
				else {
					msg.o.err = wrap_socket(&msg.o.lookup.dev.port, sock, smi->socket.type);
					msg.o.lookup.fil = msg.o.lookup.dev;
				}
				break;

			case sockmGetNameInfo:
				if (msg.i.size != sizeof(size_t) || (sz = *(size_t *)msg.i.data) > msg.o.size) {
					smo->ret = EAI_SYSTEM;
					smo->sys.err = -EINVAL;
					break;
				}

				smo->ret = do_getnameinfo(sa_convert_sys_to_lwip(smi->send.addr, smi->send.addrlen), smi->send.addrlen, msg.o.data, sz, msg.o.data + sz, msg.o.size - sz, smi->send.flags);
				smo->sys.err = smo->ret == EAI_SYSTEM ? errno : 0;
				smo->nameinfo.hostlen = sz > 0 ? strlen(msg.o.data) + 1 : 0;
				smo->nameinfo.servlen = msg.o.size - sz > 0 ? strlen(msg.o.data + sz) + 1 : 0;
				break;

#if LWIP_DNS
			case sockmGetAddrInfo:
				node = smi->socket.ai_node_sz ? msg.i.data : NULL;
				serv = msg.i.size > smi->socket.ai_node_sz ? msg.i.data + smi->socket.ai_node_sz : NULL;

				if (smi->socket.ai_node_sz > msg.i.size || (node && node[smi->socket.ai_node_sz - 1]) || (serv && ((char *)msg.i.data)[msg.i.size - 1])) {
					smo->ret = EAI_SYSTEM;
					smo->sys.err = -EINVAL;
					break;
				}

				hint.ai_flags = smi->socket.flags;
				hint.ai_family = smi->socket.domain;
				hint.ai_socktype = smi->socket.type;
				hint.ai_protocol = smi->socket.protocol;
				smo->sys.buflen = msg.o.size;
				smo->ret = do_getaddrinfo(node, serv, &hint, msg.o.data, &smo->sys.buflen);
				smo->sys.err = smo->ret == EAI_SYSTEM ? errno : 0;
				break;
#endif
			case sockmGetIfAddrs:
				smo->sys.buflen = msg.o.size;
				smo->ret = do_getifaddrs(msg.o.data, &smo->sys.buflen);
				smo->sys.err = smo->ret == EAI_SYSTEM ? errno : 0;
				break;
			default:
				msg.o.err = -EINVAL;
		}

		msgRespond(port, &msg, respid);
	}

	errout(err, "msgRecv(socketsrv)");
}


__constructor__(1000) void init_lwip_sockets(void)
{
	oid_t oid = { 0 };
	int err;

	if ((pthread_mutex_init(&sockpool.lock, NULL) != 0) || (pthread_cond_init(&sockpool.cond, NULL) != 0)) {
		errout(-ENOMEM, "socket worker pool");
	}

#if LWIP_IPSEC
	key_sockets_init();
#endif /* LWIP_IPSEC */

	if ((err = portCreate(&oid.port)) < 0)
		errout(err, "portCreate(socketsrv)");

	err = create_dev(&oid, PATH_SOCKSRV);
	if (err) {
		errout(err, "create_dev(%s)", PATH_SOCKSRV);
	}

	if ((err = sys_thread_opt_new("socketsrv", socketsrv_thread, (void *)(uintptr_t)oid.port, SOCKTHREAD_STACKSZ, SOCKTHREAD_PRIO, NULL))) {
		portDestroy(oid.port);
		errout(err, "thread(socketsrv)");
	}
}
