/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - TCP/IP thread wrapper
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "lwipopts.h"

#include "lwip/sockets.h"

#include <string.h>
#include <sys/msg.h>
#include <posix/utils.h>
#include <syslog.h>

#include "lwip/netif.h"

#include "netif-driver.h"
#include "route.h"
#include "filter.h"
#include "devs.h"
#include "wifi-api.h"
#include "ipsec-api.h"

#ifndef GENET_RX_CACHEABLE
#define GENET_RX_CACHEABLE 0
#endif
#if GENET_RX_CACHEABLE
void genet_rxcacheBench(struct netif *netif);
#endif

#ifndef LWIP_IPERF
#define LWIP_IPERF 0
#endif
#if LWIP_IPERF
#include "lwip/apps/lwiperf.h"
#include "lwip/tcpip.h"

/* Raw-TCP throughput bench report: prints the measured RX rate to the console
 * so a host `iperf -c <pi>` result is visible on the Pi UART. */
static void iperf_report(void *arg, enum lwiperf_report_type report_type,
	const ip_addr_t *local_addr, u16_t local_port,
	const ip_addr_t *remote_addr, u16_t remote_port,
	u32_t bytes_transferred, u32_t ms_duration, u32_t bandwidth_kbitpsec)
{
	(void)arg;
	(void)local_addr;
	(void)local_port;
	(void)remote_addr;
	(void)remote_port;
	printf("lwiperf: DONE type=%d bytes=%u ms=%u bw=%u kbit/s (=%u KB/s)\n",
		(int)report_type, (unsigned)bytes_transferred, (unsigned)ms_duration,
		(unsigned)bandwidth_kbitpsec, (unsigned)(bandwidth_kbitpsec / 8u));
}

/* Start the iperf2 TCP server inside the tcpip thread (raw API needs the core
 * lock; tcpip_callback runs it in the right context). */
static void iperf_start_cb(void *arg)
{
	(void)arg;
	if (lwiperf_start_tcp_server_default(iperf_report, NULL) == NULL)
		printf("lwiperf: FAILED to start TCP server\n");
	else
		printf("lwiperf: iperf2 TCP server listening on :5001\n");
}
#endif


static void mainLoop(void)
{
	msg_t msg = { 0 };
	msg_rid_t rid;
	unsigned port;

	if (portCreate(&port) < 0) {
		printf("phoenix-rtos-lwip: can't create port\n");
		return;
	}

	if (devs_init(port) < 0)
		return;

	for (;;) {
		if (msgRecv(port, &msg, &rid) < 0)
			continue;

		switch (msg.type) {
			case mtOpen:
				msg.o.err = dev_open(msg.oid.id, msg.i.openclose.flags);
				break;

			case mtClose:
				msg.o.err = dev_close(msg.oid.id);
				break;

			case mtRead:
				msg.o.err = dev_read(msg.oid.id, msg.o.data, msg.o.size, msg.i.io.offs);
				break;

			case mtWrite:
				msg.o.err = dev_write(msg.oid.id, msg.i.data, msg.i.size, msg.i.io.offs);
				break;

			default:
				break;
		}

		msgRespond(port, &msg, rid);
	}
}


int main(int argc, char **argv)
{
	size_t have_intfs = 0;

	openlog("lwip", LOG_NDELAY, LOG_DAEMON);

#ifndef HAVE_WORKING_INIT_ARRAY
	void init_lwip_tcpip(void);
	void init_lwip_sockets(void);
	void register_driver_rtl(void);
	void register_driver_enet(void);
	void register_driver_genet(void);
	void register_driver_greth(void);
	void register_driver_pppos(void);
	void register_driver_pppou(void);
	void register_driver_tun(void);
	void register_driver_tap(void);
	void register_driver_g3plc(void);

	init_lwip_tcpip();
	init_lwip_sockets();
#ifdef HAVE_DRIVER_rtl
	register_driver_rtl();
#endif
#ifdef HAVE_DRIVER_enet
	register_driver_enet();
#endif
#ifdef HAVE_DRIVER_genet
	register_driver_genet();
#endif
#ifdef HAVE_DRIVER_greth
	register_driver_greth();
#endif
#ifdef HAVE_DRIVER_pppos
	register_driver_pppos();
#endif
#ifdef HAVE_DRIVER_pppou
	register_driver_pppou();
#endif
#ifdef HAVE_DRIVER_tuntap
	register_driver_tun();
	register_driver_tap();
#endif
#ifdef HAVE_DRIVER_g3plc
	register_driver_g3plc();
#endif
#endif

	route_init();

#if LWIP_EXT_PF
	init_filters();
#endif

#if LWIP_WIFI
	init_wifi();
#endif

	while (++argv, --argc) {
		int err = create_netif(*argv);

		if (!err)
			++have_intfs;
		else
			printf("phoenix-rtos-lwip: can't init netif from cfg \"%s\": %s\n", *argv, strerror(err));
	}

	/* printf("netsrv: %zu interface%s\n", have_intfs, have_intfs == 1 ? "" : "s"); */
#if !LWIP_WIFI
	if (have_intfs == 0) {
		exit(1);
	}
#endif

#if LWIP_IPSEC
	if (ipsecdev_attach(LWIP_IPSEC_DEV) < 0) {
		printf("phoenix-rtos-lwip: can't attach IPSEC device \"%s\": %s\n", LWIP_IPSEC_DEV, strerror(errno));
	}
#endif

#if GENET_RX_CACHEABLE
	/* Policy B integrity + throughput bench. Resolves the gateway itself once
	 * DHCP completes; netif_default is the genet interface here. */
	genet_rxcacheBench(netif_default);
#endif

#if LWIP_IPERF
	tcpip_callback(iperf_start_cb, NULL);
#endif

	mainLoop();

	return 1;
}
