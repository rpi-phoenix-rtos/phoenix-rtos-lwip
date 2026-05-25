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

#include <sys/mman.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/threads.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>


#define DIAG_UDP_PORT 9999u
#define DIAG_REPLY_MAX 1400u  /* one fragment of stock 1500B MTU */
#define DIAG_BURN_THREADS 4
#define DIAG_BURN_DURATION_US (10ULL * 1000000ULL)  /* 10 s */
#define DIAG_BURN_STACK 1024u


static struct udp_pcb *diag_pcb;
static time_t diag_boot_us;
static volatile int diag_burn_active;
static volatile time_t diag_burn_deadline_us;

/* One counter per cache line. Without the padding all 4 slots fit in
 * one 64-byte L1 line and every burner thread's per-iteration RMW
 * invalidates the other 3 cores' caches — millions of cycles per
 * effective increment, with frequent lost updates from non-atomic
 * load-add-store. With the padding (this struct), four cores each
 * own their own cache line and the inner loop runs at ALU speed.
 * See `docs/notes/2026-05-25-pi4-userspace-shareability.md`. */
static struct {
	unsigned long long c;
	char pad[64 - sizeof(unsigned long long)];
} __attribute__((aligned(64))) diag_burn_counters[DIAG_BURN_THREADS];

static uint32_t diag_burn_stacks[DIAG_BURN_THREADS][DIAG_BURN_STACK]
	__attribute__((aligned(16)));


/* SMP Phase E saturation thread. Spawned by the 'b' command. Each
 * instance pins itself to a busy loop incrementing a counter for
 * DIAG_BURN_DURATION_US wall-clock microseconds. The kernel's per-CPU
 * scheduler is expected to place each on its own core; verified
 * externally by paired 't' probes seeing each [burner-N] thread's
 * cpuTime advance at ~wall-clock rate. */
static void diag_burnThread(void *arg)
{
	unsigned slot = (unsigned)(uintptr_t)arg;
	time_t now_us;
	unsigned long long local = 0;

	for (;;) {
		gettime(&now_us, NULL);
		if (now_us >= diag_burn_deadline_us) {
			break;
		}
		/* Plain inner loop on the cache-line-padded slot. Per-thread
		 * cache lines mean no inter-CPU coherence traffic; the loop
		 * runs at ALU speed (~3 cycles per iteration on the A72). */
		for (int i = 0; i < 4096; ++i) {
			local++;
			diag_burn_counters[slot].c++;
		}
	}

	(void)local;

	if (__atomic_sub_fetch(&diag_burn_active, 1, __ATOMIC_RELAXED) == 0) {
		/* Last burner out — leave counters readable by future
		 * 't' probes; no cleanup needed. */
	}

	endthread();
}


static int diag_format_burn(char *buf, size_t cap)
{
	int r, off = 0;
	time_t now_us;

	gettime(&now_us, NULL);
	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 burn\n");
	if (r < 0) {
		return -1;
	}
	off += r;

	if (diag_burn_active > 0) {
		long long remaining = (long long)diag_burn_deadline_us - (long long)now_us;
		r = snprintf(buf + off, cap - off,
			"burners_active: %d\nremaining_us: %lld\n",
			diag_burn_active, remaining > 0 ? remaining : 0);
	}
	else {
		/* Spawn fresh burner cohort. */
		int spawned = 0;
		diag_burn_deadline_us = now_us + (time_t)DIAG_BURN_DURATION_US;
		for (int i = 0; i < DIAG_BURN_THREADS; ++i) {
			diag_burn_counters[i].c = 0;
		}
		for (int i = 0; i < DIAG_BURN_THREADS; ++i) {
			int err = beginthread(diag_burnThread, 4,
				diag_burn_stacks[i], sizeof(diag_burn_stacks[i]),
				(void *)(uintptr_t)i);
			if (err == 0) {
				spawned++;
			}
		}
		__atomic_store_n(&diag_burn_active, spawned, __ATOMIC_RELAXED);
		r = snprintf(buf + off, cap - off,
			"spawned: %d/%d\nduration_us: %llu\n",
			spawned, DIAG_BURN_THREADS,
			(unsigned long long)DIAG_BURN_DURATION_US);
	}
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	for (int i = 0; i < DIAG_BURN_THREADS; ++i) {
		r = snprintf(buf + off, cap - off,
			"burner%d_count: %llu\n", i, diag_burn_counters[i].c);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
	}

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


/* Comparator for qsort: largest cpuTime first. */
static int diag_threads_cmp(const void *a, const void *b)
{
	const threadinfo_t *ta = a;
	const threadinfo_t *tb = b;
	if (tb->cpuTime > ta->cpuTime) {
		return 1;
	}
	if (tb->cpuTime < ta->cpuTime) {
		return -1;
	}
	return 0;
}


/* Format reply for the 't' query — top threads by accumulated CPU time.
 * Output format:
 *   PHX-DIAG/1 threads
 *   thread: pid=<n> tid=<n> load=<%> cpuTime_us=<n> name=<s>
 *   ...repeated for top N...
 *   uptime_ms: <n>
 *   .
 * The cpuTime delta between two queries divided by wall-clock delta is
 * the per-thread fraction-of-a-core consumed; sum across CPU-bound
 * threads is the cross-CPU distribution metric for SMP Phase E. */
static int diag_format_threads(char *buf, size_t cap)
{
	enum { TOP_N = 12, MAX_THREADS = 128 };
	threadinfo_t *info;
	int n, written, off = 0, r;
	time_t now_us;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 threads\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	info = malloc(MAX_THREADS * sizeof(threadinfo_t));
	if (info == NULL) {
		r = snprintf(buf + off, cap - off, "error: out of memory\n.\n");
		return off + (r > 0 ? r : 0);
	}

	n = threadsinfo(MAX_THREADS, info);
	if (n < 0) {
		r = snprintf(buf + off, cap - off, "error: threadsinfo=%d\n.\n", n);
		free(info);
		return off + (r > 0 ? r : 0);
	}

	qsort(info, n, sizeof(threadinfo_t), diag_threads_cmp);

	written = (n < TOP_N) ? n : TOP_N;
	for (int i = 0; i < written; ++i) {
		r = snprintf(buf + off, cap - off,
			"thread: pid=%u tid=%u load=%d cpuTime_us=%llu name=%.40s\n",
			(unsigned)info[i].pid, (unsigned)info[i].tid,
			info[i].load, (unsigned long long)info[i].cpuTime,
			info[i].name);
		if (r < 0 || (size_t)r >= cap - off) {
			break;
		}
		off += r;
	}

	gettime(&now_us, NULL);
	r = snprintf(buf + off, cap - off,
		"total_threads: %d\nuptime_ms: %llu\n.\n",
		n, (unsigned long long)((now_us - diag_boot_us) / 1000ULL));
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	free(info);
	return off;
}


/* WiFi Tier 1a scout: probe VideoCore mailbox for EMMC/EMMC2 clock
 * state, then attempt to read SDHCI VERSION/CAPS now that we know
 * the controller is alive. Earlier extended scout (with VERSION at
 * 0xFC) faulted because the clock was off; the 'c' sub-command first
 * asks the firmware for clock rate, and only attempts the high-offset
 * reads if a non-zero rate is reported.
 *
 * Pi 4 mailbox base (board_config.h would expose this, but the port
 * doesn't have that include path — hardcoded with a comment). */
#define RPI_PI4_MAILBOX_BASE  0xfe00b880u

#define VC_MBOX_READ          0x00u
#define VC_MBOX_STATUS        0x18u
#define VC_MBOX_WRITE         0x20u
#define VC_MBOX_STATUS_FULL   0x80000000u
#define VC_MBOX_STATUS_EMPTY  0x40000000u
#define VC_MBOX_RESP_OK       0x80000000u
#define VC_MBOX_PROP_CHANNEL  8u

#define VC_PROP_GET_CLOCK_RATE 0x00030002u
#define VC_PROP_GET_POWER_STATE 0x00020001u
#define VC_PROP_SET_POWER_STATE 0x00028001u

#define VC_CLOCK_EMMC   1u
#define VC_CLOCK_EMMC2  12u

#define VC_DEV_SDCARD   0u  /* SDHCI @ 0xfe300000 power domain */


static uint32_t diag_mboxGetClockRate(uint32_t clock_id)
{
	addr_t pa_base = (addr_t)RPI_PI4_MAILBOX_BASE & ~(addr_t)(_PAGE_SIZE - 1);
	addr_t pa_offs = (addr_t)RPI_PI4_MAILBOX_BASE & (addr_t)(_PAGE_SIZE - 1);
	volatile uint32_t *mbox;
	uint32_t *msg;
	uintptr_t msg_pa;
	uint32_t request;
	uint32_t rate = 0xFFFFFFFFu;
	void *mbox_page;
	void *msg_page;

	mbox_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, pa_base);
	if (mbox_page == MAP_FAILED) {
		return 0xFFFFFFFFu;
	}
	mbox = (volatile uint32_t *)((volatile uint8_t *)mbox_page + pa_offs);

	/* Property message buffer (16-byte aligned, uncached). */
	msg_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_UNCACHED | MAP_CONTIGUOUS | MAP_ANONYMOUS, -1, 0);
	if (msg_page == MAP_FAILED) {
		munmap(mbox_page, _PAGE_SIZE);
		return 0xFFFFFFFFu;
	}
	msg = msg_page;

	/* GET_CLOCK_RATE packet: clock-id sent, rate returned (Hz). */
	msg[0] = 32;
	msg[1] = 0;
	msg[2] = VC_PROP_GET_CLOCK_RATE;
	msg[3] = 8;
	msg[4] = 0;
	msg[5] = clock_id;
	msg[6] = 0;
	msg[7] = 0;

	msg_pa = (uintptr_t)va2pa(msg);
	if (msg_pa == (uintptr_t)-1) {
		munmap(msg_page, _PAGE_SIZE);
		munmap(mbox_page, _PAGE_SIZE);
		return 0xFFFFFFFFu;
	}
	request = ((uint32_t)msg_pa & ~0xFu) | VC_MBOX_PROP_CHANNEL;

	while ((mbox[VC_MBOX_STATUS / 4] & VC_MBOX_STATUS_FULL) != 0u) {
	}
	mbox[VC_MBOX_WRITE / 4] = request;

	for (;;) {
		while ((mbox[VC_MBOX_STATUS / 4] & VC_MBOX_STATUS_EMPTY) != 0u) {
		}
		if (mbox[VC_MBOX_READ / 4] == request) {
			break;
		}
	}

	if (msg[1] == VC_MBOX_RESP_OK) {
		rate = msg[6];  /* response rate (Hz) */
	}

	munmap(msg_page, _PAGE_SIZE);
	munmap(mbox_page, _PAGE_SIZE);
	return rate;
}


/* Get / set VideoCore device power state. Tag, device_id, and state
 * are passed in `tag`/`device_id`/`state` (state ignored for GET).
 * Returns the resulting state on success, 0xFFFFFFFF on failure. */
static uint32_t diag_mboxPower(uint32_t tag, uint32_t device_id, uint32_t state)
{
	addr_t pa_base = (addr_t)RPI_PI4_MAILBOX_BASE & ~(addr_t)(_PAGE_SIZE - 1);
	addr_t pa_offs = (addr_t)RPI_PI4_MAILBOX_BASE & (addr_t)(_PAGE_SIZE - 1);
	volatile uint32_t *mbox;
	uint32_t *msg;
	uintptr_t msg_pa;
	uint32_t request;
	uint32_t result = 0xFFFFFFFFu;
	void *mbox_page;
	void *msg_page;

	mbox_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, pa_base);
	if (mbox_page == MAP_FAILED) {
		return 0xFFFFFFFFu;
	}
	mbox = (volatile uint32_t *)((volatile uint8_t *)mbox_page + pa_offs);

	msg_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_UNCACHED | MAP_CONTIGUOUS | MAP_ANONYMOUS, -1, 0);
	if (msg_page == MAP_FAILED) {
		munmap(mbox_page, _PAGE_SIZE);
		return 0xFFFFFFFFu;
	}
	msg = msg_page;

	/* GET takes (device_id) and returns (device_id, state).
	 * SET takes (device_id, state) and returns (device_id, state). */
	msg[0] = 32;
	msg[1] = 0;
	msg[2] = tag;
	msg[3] = 8;
	msg[4] = 0;
	msg[5] = device_id;
	msg[6] = state;
	msg[7] = 0;

	msg_pa = (uintptr_t)va2pa(msg);
	if (msg_pa == (uintptr_t)-1) {
		munmap(msg_page, _PAGE_SIZE);
		munmap(mbox_page, _PAGE_SIZE);
		return 0xFFFFFFFFu;
	}
	request = ((uint32_t)msg_pa & ~0xFu) | VC_MBOX_PROP_CHANNEL;

	while ((mbox[VC_MBOX_STATUS / 4] & VC_MBOX_STATUS_FULL) != 0u) {
	}
	mbox[VC_MBOX_WRITE / 4] = request;

	for (;;) {
		while ((mbox[VC_MBOX_STATUS / 4] & VC_MBOX_STATUS_EMPTY) != 0u) {
		}
		if (mbox[VC_MBOX_READ / 4] == request) {
			break;
		}
	}

	if (msg[1] == VC_MBOX_RESP_OK) {
		result = msg[6];  /* returned state */
	}

	munmap(msg_page, _PAGE_SIZE);
	munmap(mbox_page, _PAGE_SIZE);
	return result;
}


static int diag_format_clocks(char *buf, size_t cap)
{
	int off = 0, r;
	uint32_t rate_emmc, rate_emmc2;
	uint32_t pwr_before, pwr_set;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 clocks\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	rate_emmc  = diag_mboxGetClockRate(VC_CLOCK_EMMC);
	rate_emmc2 = diag_mboxGetClockRate(VC_CLOCK_EMMC2);

	r = snprintf(buf + off, cap - off,
		"EMMC  (id=1) : rate_hz = %u\n"
		"EMMC2 (id=12): rate_hz = %u\n",
		(unsigned)rate_emmc, (unsigned)rate_emmc2);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	/* Probe SD-card device power state, then attempt SET=on (state bit
	 * 0 = on, bit 1 = wait-for-stable). Both GET and SET return the
	 * resulting (or current) state. */
	pwr_before = diag_mboxPower(VC_PROP_GET_POWER_STATE, VC_DEV_SDCARD, 0);
	pwr_set    = diag_mboxPower(VC_PROP_SET_POWER_STATE, VC_DEV_SDCARD, 3);

	r = snprintf(buf + off, cap - off,
		"SDCard power: before=0x%x after_set=0x%x\n",
		(unsigned)pwr_before, (unsigned)pwr_set);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


/* WiFi Tier 0 scout: dump Pi 4 GPFSEL3/4 + register-zero reads from
 * candidate MMC/SDIO host controllers, to determine which one is
 * wired to the BCM43455 on this board.
 *
 *   GPFSEL3 @ 0x7e20000c  controls function-select for GPIO 30..39
 *   GPFSEL4 @ 0x7e200010  controls function-select for GPIO 40..49
 *
 *   SDHOST  @ 0xfe202000  bcm2835-style legacy MMC controller — Linux
 *                         uses it for SD card by default on Pi 4
 *   SDIO/EMMC2 (Arasan) @ 0xfe340000  used for WiFi on Pi 4 per
 *                         raspberrypi/linux dts files
 *
 * (Notes: 0xfe300000 is occasionally cited as a third controller in
 * older docs; on BCM2711 Linux DT, EMMC2 is at 0xfe340000.) */
static int diag_format_sdio_scout(char *buf, size_t cap)
{
	int off = 0, r;
	/* Only read register 0 of each controller. Some BCM2711 controllers
	 * fault on reads when held in reset / clock-gated, so don't poke
	 * at high offsets blindly. We also dump the GPFSEL bits that
	 * route pins to SD/MMC alt functions. */
	struct probe {
		const char *name;
		addr_t pa;
	} probes[] = {
		{ "GPFSEL3",   0xfe20000cu },  /* GPIO 30..39 fn-sel */
		{ "GPFSEL4",   0xfe200010u },  /* GPIO 40..49 fn-sel */
		{ "SDHOST_0",  0xfe202000u },  /* bcm2835 SDHOST (typically SD) */
		{ "SDHCI_0",   0xfe300000u },  /* legacy SDHCI (Pi 3 EMMC) */
		{ "EMMC2_0",   0xfe340000u },  /* BCM2711 EMMC2 (typically WiFi) */
		{ NULL, 0 },
	};

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-scout\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	for (int i = 0; probes[i].name != NULL; ++i) {
		addr_t pa_base = probes[i].pa & ~(addr_t)(_PAGE_SIZE - 1);
		addr_t pa_offs = probes[i].pa & (addr_t)(_PAGE_SIZE - 1);
		void *page;
		uint32_t val = 0xDEADBEEFu;
		int ok = 0;

		page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
			-1, pa_base);
		if (page != MAP_FAILED) {
			val = *(volatile uint32_t *)((volatile uint8_t *)page + pa_offs);
			munmap(page, _PAGE_SIZE);
			ok = 1;
		}

		r = snprintf(buf + off, cap - off, "%s @ 0x%08x = 0x%08x%s\n",
			probes[i].name, (unsigned)probes[i].pa,
			(unsigned)val, ok ? "" : " (mmap failed)");
		if (r < 0 || (size_t)r >= cap - off) {
			break;
		}
		off += r;
	}

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


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
	char query;

	(void)arg;

	/* Peek the first byte of the request to pick the response shape.
	 *   't' → thread/cpu stats
	 *   anything else → netif stats (default) */
	query = 0;
	if (p->len >= 1) {
		query = ((const char *)p->payload)[0];
	}
	pbuf_free(p);

	reply = pbuf_alloc(PBUF_TRANSPORT, DIAG_REPLY_MAX, PBUF_RAM);
	if (reply == NULL) {
		return;
	}

	body = (char *)reply->payload;
	if (query == 't') {
		len = diag_format_threads(body, DIAG_REPLY_MAX);
	}
	else if (query == 'b') {
		len = diag_format_burn(body, DIAG_REPLY_MAX);
	}
	else if (query == 's') {
		len = diag_format_sdio_scout(body, DIAG_REPLY_MAX);
	}
	else if (query == 'c') {
		len = diag_format_clocks(body, DIAG_REPLY_MAX);
	}
	else {
		len = diag_format_reply(body, DIAG_REPLY_MAX);
	}
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
