/*
 * Phoenix-RTOS --- LwIP port
 *
 * Diagnostic UDP responder.
 *
 * Listens on UDP port 9999 (any interface). Every inbound datagram
 * triggers a single-shot text reply containing one line per registered
 * netif with its standard MIB-2 counters (rx/tx packets/bytes/drops) and
 * a final uptime line.
 *
 * Rationale: on post-fbcon Pi 4 boots the pl011 UART no longer captures
 * userspace stdout — this is a Phoenix-side limitation (psh / ttyfs
 * routing, tracked elsewhere). With the GENET driver running we can
 * recover observability over the network without touching the
 * upstream-side console plumbing. The responder uses LwIP's raw UDP
 * API (LWIP_TCPIP_CORE_LOCKING is on for this port) so the callback
 * runs in the tcpip-thread context — no extra threads, no socket
 * descriptors.
 *
 * Wire format (ASCII, line-oriented):
 *
 *   PHX-DIAG/1\n
 *   netif: <name><num> rx=<pkts> rx_bytes=<bytes> rx_drop=<n>
 *          tx=<pkts> tx_bytes=<bytes> tx_drop=<n>\n
 *   ...repeated per netif...
 *   uptime_ms: <n>\n
 *   .\n
 *
 * Host-side probe (no extra tooling needed):
 *
 *   $ echo q | nc -u -w1 10.42.0.99 9999
 *
 * Copyright 2026 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "lwip/udp.h"
#include "lwip/netif.h"
#include "lwip/tcpip.h"
#include "lwip/stats.h"
#include "netif-driver.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>


#define DIAG_UDP_PORT 9999u
#define DIAG_REPLY_MAX 1400u  /* one fragment of stock 1500B MTU */


static struct udp_pcb *diag_pcb;
static time_t diag_boot_us;


static int diag_format_reply(char *buf, size_t cap)
{
	struct netif *n;
	int off = 0;
	int r;
	time_t now_us;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	NETIF_FOREACH(n) {
		char drv_stats[256];
		int drv_len = 0;

		/* Only netifs created via create_netif() have the netif_alloc
		 * wrapper that netif_driver() expects. The loopback netif
		 * (lwip's own netif_init_loopif) has no wrapper — calling
		 * netif_driver() on it reads past the struct and dereferences
		 * a wild pointer. Gate on NETIF_FLAG_ETHARP, which is set by
		 * every Phoenix netif-driver but not by loopback. */
		if ((n->flags & NETIF_FLAG_ETHARP) != 0) {
			netif_driver_t *drv = netif_driver(n);
			if (drv != NULL && drv->stats != NULL) {
				drv_len = drv->stats(n, drv_stats, sizeof(drv_stats));
			}
		}

		if (drv_len > 0) {
			r = snprintf(buf + off, cap - off,
				"netif: %c%c%u %s\n",
				n->name[0], n->name[1], (unsigned)n->num, drv_stats);
		}
		else {
			r = snprintf(buf + off, cap - off,
				"netif: %c%c%u (no per-driver stats)\n",
				n->name[0], n->name[1], (unsigned)n->num);
		}
		if (r < 0 || (size_t)r >= cap - off) {
			break;
		}
		off += r;
	}

	gettime(&now_us, NULL);
	r = snprintf(buf + off, cap - off, "uptime_ms: %llu\n.\n",
		(unsigned long long)((now_us - diag_boot_us) / 1000ULL));
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	return off;
}


static void diag_udp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
	const ip_addr_t *addr, u16_t port)
{
	struct pbuf *reply;
	int len;
	char *body;

	(void)arg;
	pbuf_free(p);

	reply = pbuf_alloc(PBUF_TRANSPORT, DIAG_REPLY_MAX, PBUF_RAM);
	if (reply == NULL) {
		return;
	}

	body = (char *)reply->payload;
	len = diag_format_reply(body, DIAG_REPLY_MAX);
	if (len <= 0) {
		pbuf_free(reply);
		return;
	}
	pbuf_realloc(reply, (u16_t)len);

	(void)udp_sendto(pcb, reply, addr, port);
	pbuf_free(reply);
}


static void diag_udp_setup_cb(void *arg)
{
	err_t err;

	(void)arg;

	diag_pcb = udp_new();
	if (diag_pcb == NULL) {
		printf("phoenix-rtos-lwip: diag-udp udp_new failed\n");
		return;
	}

	err = udp_bind(diag_pcb, IP_ANY_TYPE, DIAG_UDP_PORT);
	if (err != ERR_OK) {
		printf("phoenix-rtos-lwip: diag-udp bind: %d\n", (int)err);
		udp_remove(diag_pcb);
		diag_pcb = NULL;
		return;
	}

	udp_recv(diag_pcb, diag_udp_recv, NULL);
}


void init_diag_udp(void)
{
	gettime(&diag_boot_us, NULL);
	(void)tcpip_callback(diag_udp_setup_cb, NULL);
}
