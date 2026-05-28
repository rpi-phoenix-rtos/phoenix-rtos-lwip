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

#include "netif-driver.h"
#include "route.h"
#include "filter.h"
#include "devs.h"
#include "wifi-api.h"
#include "ipsec-api.h"


#ifdef LWIP_EMBED_USB
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/threads.h>

/* Embedded Phoenix-RTOS USB host stack — see port/Makefile and the
 * shim files in port/usb-embed/. usb_init() is the stack entry point
 * (defined in phoenix-rtos-usb/usb/usb.c, declared in usbhost.h). */
extern int usb_init(void);

/* Diagnostic: the proven-working X-diag rig from diag-udp.c. Calling
 * it directly from this worker lets us A/B test in the same boot:
 * "does the rig still succeed under BRIDGE_ONLY?" without needing to
 * wait for a manual UDP trigger and without racing usb_init. */
extern int diag_format_xhci_bringup(char *buf, size_t cap);

static uint8_t lwip_embed_usb_stack[16 * 1024];
static char lwip_embed_rig_buf[8192];

static void lwip_embed_usb_thread(void *arg)
{
	(void)arg;
	/* Pi 4 PoC: this lwip-port process hosts the USB host stack. The
	 * boot-time `usb;--bridge-only` daemon has already done the one-shot
	 * BCM2711 PCIe bridge bring-up and exited cleanly (without touching
	 * the controller — see BCM2711_USB_BRIDGE_ONLY in xhci_init). We
	 * deliberately do NOT set USB_HCD_PCIE_DRIVE_ONLY here: we want this
	 * process to re-run bcm2711_pcie_initVL805 in-process, matching the
	 * known-good 'X' diag rig sequence where bridge bring-up + controller
	 * drive happen in the SAME process. Empirically a controller-drive-
	 * only process on BCM2711 has its inbound DMA writes silently lost,
	 * so per-process bridge init is load-bearing for this PoC.
	 *
	 * GENET-warm-up delay (10 s): the 'X' diag rig works reliably when
	 * triggered ~minutes after boot but fails when run immediately at
	 * lwip startup; the leading hypothesis is that the SCB→DDR fabric
	 * shared by GENET and the PCIe RC needs GENET to be actively
	 * cycling before the VL805's inbound DMA writes reach DRAM. Give
	 * lwip + DHCP + ARP a head start before we open the xHCI bring-up
	 * race. Tune downward later once we confirm whether the delay
	 * changes the outcome.
	 *
	 * usb_init() spawns N-1 status threads + msgthr internally; this
	 * wrapper exits after a successful init. */
	sleep(10);
	/* DIAGNOSTIC SEQUENCE: rig → usb_init. The rig is known-working
	 * from this exact worker context (proven by the rig-in-worker test
	 * which enumerated a real USB hub). Run it first to confirm the
	 * controller can be brought up in this process. Then attempt the
	 * real usb_init/xhci_init path. The rig's HCRST + USBCMD=R/S
	 * sequence leaves the controller in a running state with one slot
	 * enabled and one device addressed — usb_init's first act
	 * (xhci_init) does its OWN HCRST so everything is reset back, but
	 * any state that survives HCRST (e.g. bridge translation, VL805
	 * firmware internals) will already be in the rig-success
	 * configuration when xhci_init's sequence runs. */
	printf("phoenix-rtos-lwip: starting embedded USB host stack...\n");
	if (usb_init() != 0) {
		printf("phoenix-rtos-lwip: embedded usb_init() failed\n");
	}
	else {
		printf("phoenix-rtos-lwip: embedded usb_init() SUCCEEDED\n");
	}
	(void)lwip_embed_rig_buf;
	(void)diag_format_xhci_bringup;
	/* Phoenix beginthread'd functions must not return — falling off the
	 * end jumps to a poisoned lr (PC alignment fault). Park here. */
	for (;;) {
		usleep(60u * 1000u * 1000u);
	}
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

	/* Network-routed observability — a UDP responder on port 9999.
	 * Survives the post-fbcon UART silence on Pi 4 and gives the host
	 * a way to read per-netif counters with `nc -u`. Side-effect-free
	 * on systems with at least one interface up. */
	if (have_intfs > 0) {
		void init_diag_udp(void);
		init_diag_udp();
	}

#ifdef LWIP_EMBED_USB
	/* Pi 4 PoC: spawn the embedded USB host stack in this process. The
	 * worker thread does the setenv + usb_init() call; see the
	 * lwip_embed_usb_thread comment above for rationale. Failure to
	 * spawn here is not fatal — networking still works. */
	if (beginthread(lwip_embed_usb_thread, 4, lwip_embed_usb_stack,
			sizeof(lwip_embed_usb_stack), NULL) != 0) {
		printf("phoenix-rtos-lwip: failed to spawn embedded USB thread\n");
	}
#endif

	mainLoop();

	return 1;
}
