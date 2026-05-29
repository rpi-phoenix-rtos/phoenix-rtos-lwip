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
#include <unistd.h>
#include <sys/threads.h>

/* Embedded Phoenix-RTOS USB host stack — see port/Makefile and the
 * shim files in port/usb-embed/. usb_init() is the stack entry point
 * (defined in phoenix-rtos-usb/usb/usb.c, declared in usbhost.h). */
extern int usb_init(void);

static uint8_t lwip_embed_usb_stack[16 * 1024];

static void lwip_embed_usb_thread(void *arg)
{
	(void)arg;
	/* Pi 4 PoC: this lwip-port process hosts the USB host stack. The
	 * boot-time `usb;--bridge-only` daemon has already done the one-shot
	 * BCM2711 PCIe bridge bring-up and parked (without touching the
	 * controller — see BCM2711_USB_BRIDGE_ONLY in xhci_init). This thread
	 * then sets USB_HCD_PCIE_DRIVE_ONLY (below) so it drives ONLY the
	 * controller on the already-brought-up bridge, rather than re-running
	 * the bridge bring-up itself. (An earlier approach had this process
	 * re-run bcm2711_pcie_initVL805 in-process; DRIVE_ONLY was adopted to
	 * eliminate that bridge re-init as a variable.)
	 *
	 * NOTE: neither arrangement enumerates USB — the controller runs but
	 * its inbound DMA event-ring writes never land (`first event @idx -1`,
	 * rc=-110). The root cause is unresolved and JTAG-gated; see
	 * docs/notes/2026-05-29-usb-reanalysis.md.
	 *
	 * GENET-warm-up delay (10 s): gives lwip + DHCP + ARP a head start
	 * before the xHCI bring-up. NOTE (2026-05-29): the old rationale —
	 * "the SCB→DDR fabric needs GENET actively cycling before the VL805's
	 * inbound DMA writes reach DRAM" — was DISPROVEN. A sustained GENET TX
	 * DMA flood (14877 broadcast sends, 0 failures, confirmed active via
	 * debug()) running concurrently with the bring-up still produced
	 * `first event @idx -1`. The rig's "works when triggered later"
	 * correlation is most likely its own ~50% bridge flakiness, not
	 * DMA-enablement. See docs/notes/2026-05-29-usb-reanalysis.md.
	 *
	 * usb_init() spawns N-1 status threads + msgthr internally; this
	 * wrapper exits after a successful init. */
	sleep(10);
	/* MULTI-TRIAL BENCH RESULTS (2026-05-28):
	 *   PoC full bring-up:      0/8 trials succeed
	 *   PoC DRIVE_ONLY:         0/4 trials succeed
	 *   PoC MaxSlotsEn=1:       0/2 trials succeed
	 *   PoC contig scratchpad:  0/4 trials succeed
	 *   PoC no-bridge-mmap:     0/3 trials succeed
	 *   'X' diag rig:           2/4 trials succeed (~50% flakiness)
	 *
	 * The PoC consistently fails to enumerate USB while the rig
	 * succeeds about half the time on the same hardware/boot. The
	 * single-variable code paths I can identify as different from the
	 * rig (MaxSlotsEn, scratchpad layout, bridge re-init, leaked
	 * bridge mmap) are not the culprit. The remaining difference is
	 * higher up in the stack — possibly the cumulative effect of
	 * usb_init's earlier allocations (mutex pool, driver registration,
	 * hub_init) changing kernel/process state vs the rig's clean-slate
	 * mmap calls. Investigation parked pending a fresh angle.
	 *
	 * Keep DRIVE_ONLY here as it eliminates a few variables without
	 * regressing. */
	setenv("USB_HCD_PCIE_DRIVE_ONLY", "1", 1);
	printf("phoenix-rtos-lwip: starting embedded USB host stack (DRIVE_ONLY)...\n");
	if (usb_init() != 0) {
		printf("phoenix-rtos-lwip: embedded usb_init() failed\n");
	}
	else {
		printf("phoenix-rtos-lwip: embedded usb_init() SUCCEEDED\n");
	}
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
