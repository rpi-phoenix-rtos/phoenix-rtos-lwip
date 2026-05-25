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


/* BCM2711 GPIO block. Per docs/research/gpio-pinctrl.md. The block
 * exposes 54 lines as two banks (0..27 and 28..53). Pi 4 added
 * GPIO_PUP_PDN_CNTRL_REGn at 0xE4..0xF0 — the legacy GPPUD/GPPUDCLK
 * sequence is RAZ/WI on BCM2711.
 *
 * Function-select encoding (3 bits per pin in GPFSELn):
 *   0 = INPUT
 *   1 = OUTPUT
 *   2 = ALT5
 *   3 = ALT4
 *   4 = ALT0
 *   5 = ALT1
 *   6 = ALT2
 *   7 = ALT3   <- the SDIO function for GPIO 34..39 on Pi 4
 *
 * The 'g' command reads GPFSEL0..5 + GPLEV0/1 + GPIO_PUP_PDN_CNTRL_REG0..3
 * to give a full picture of pin function / level / pull state. */
#define BCM2711_GPIO_BASE   0xfe200000u

#define GPIO_GPFSEL0        0x00u   /* +4*n for GPFSEL1..5 */
#define GPIO_GPSET0         0x1cu   /* +4 for GPSET1 (lines 32..53) */
#define GPIO_GPCLR0         0x28u   /* +4 for GPCLR1 */
#define GPIO_GPLEV0         0x34u   /* +4 for GPLEV1 */
#define GPIO_PUP_PDN_CNTRL  0xe4u   /* +4*n for REG1..3 */


/* Set pin function-select (3 bits). pin: 0..53, fn: 0..7. Read-
 * modify-write of GPFSEL(pin/10). Unused yet — kept for WiFi Tier 1c
 * (will route GPIO 34..39 to ALT3 for SDIO). */
__attribute__((unused))
static void diag_gpioSetFsel(volatile uint8_t *base, unsigned pin, unsigned fn)
{
	unsigned bank = pin / 10u;
	unsigned shift = (pin % 10u) * 3u;
	volatile uint32_t *reg = (volatile uint32_t *)(base + GPIO_GPFSEL0 + bank * 4u);
	uint32_t v = *reg;
	v &= ~(0x7u << shift);
	v |= ((fn & 0x7u) << shift);
	*reg = v;
}


/* Get current function select for pin (returns 0..7). */
static unsigned diag_gpioGetFsel(volatile uint8_t *base, unsigned pin)
{
	unsigned bank = pin / 10u;
	unsigned shift = (pin % 10u) * 3u;
	volatile uint32_t *reg = (volatile uint32_t *)(base + GPIO_GPFSEL0 + bank * 4u);
	return (*reg >> shift) & 0x7u;
}


/* Set pin pull (encoding: 0=off, 1=up, 2=down — per BCM2711 docs).
 * Two bits per pin in GPIO_PUP_PDN_CNTRL_REG(pin/16). Unused yet —
 * kept for WiFi Tier 1c (SDIO pin pull-up sequencing). */
__attribute__((unused))
static void diag_gpioSetPull(volatile uint8_t *base, unsigned pin, unsigned pull)
{
	unsigned reg_idx = pin / 16u;
	unsigned shift = (pin % 16u) * 2u;
	volatile uint32_t *reg = (volatile uint32_t *)(base + GPIO_PUP_PDN_CNTRL + reg_idx * 4u);
	uint32_t v = *reg;
	v &= ~(0x3u << shift);
	v |= ((pull & 0x3u) << shift);
	*reg = v;
}


static int diag_format_gpio(char *buf, size_t cap)
{
	void *page;
	int off = 0, r;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 gpio\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, BCM2711_GPIO_BASE);
	if (page == MAP_FAILED) {
		r = snprintf(buf + off, cap - off, "error: GPIO mmap failed\n.\n");
		return off + (r > 0 ? r : 0);
	}

	{
		volatile uint8_t *base = (volatile uint8_t *)page;
		uint32_t fsel[6];
		uint32_t lev[2];
		uint32_t pup[4];
		int i;

		for (i = 0; i < 6; ++i) {
			fsel[i] = *(volatile uint32_t *)(base + GPIO_GPFSEL0 + i * 4u);
		}
		for (i = 0; i < 2; ++i) {
			lev[i] = *(volatile uint32_t *)(base + GPIO_GPLEV0 + i * 4u);
		}
		for (i = 0; i < 4; ++i) {
			pup[i] = *(volatile uint32_t *)(base + GPIO_PUP_PDN_CNTRL + i * 4u);
		}

		r = snprintf(buf + off, cap - off,
			"GPFSEL0..5: %08x %08x %08x %08x %08x %08x\n"
			"GPLEV0/1:   %08x %08x\n"
			"PUP_PDN0..3: %08x %08x %08x %08x\n",
			fsel[0], fsel[1], fsel[2], fsel[3], fsel[4], fsel[5],
			lev[0], lev[1],
			pup[0], pup[1], pup[2], pup[3]);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}

		/* Decode the GPIO 34..39 (SDIO/WiFi) function-select bits
		 * specifically — those are the ones we need to flip to ALT3
		 * for WiFi Tier 1c. */
		r = snprintf(buf + off, cap - off,
			"sdio pins fsel (need ALT3=7):  gpio34=%u gpio35=%u gpio36=%u gpio37=%u gpio38=%u gpio39=%u\n",
			diag_gpioGetFsel(base, 34),
			diag_gpioGetFsel(base, 35),
			diag_gpioGetFsel(base, 36),
			diag_gpioGetFsel(base, 37),
			diag_gpioGetFsel(base, 38),
			diag_gpioGetFsel(base, 39));
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
	}

	munmap(page, _PAGE_SIZE);
	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


/* BCM2711 PM block (watchdog + soft reset + halt). Address range
 * mapped via mmap on demand from the 'r' / 'h' handlers.
 *   PM_RSTC at offset 0x1c — reset control
 *   PM_RSTS at offset 0x20 — reset status / halt magic channel
 *   PM_WDOG at offset 0x24 — countdown register
 *   PM_PASSWORD = 0x5a000000 — top byte required on every write */
#define BCM2711_PM_BASE             0xfe100000u
#define BCM2711_PM_RSTC             0x1cu
#define BCM2711_PM_RSTS             0x20u
#define BCM2711_PM_WDOG             0x24u

#define PM_PASSWORD                 0x5a000000u
#define PM_RSTC_WRCFG_CLR           0xffffffcfu
#define PM_RSTC_WRCFG_FULL_RESET    0x00000020u
#define PM_RSTS_RASPBERRYPI_HALT    0x00000555u


/* Trigger a watchdog-driven reset. If `halt` is set, stamp the HALT
 * magic into PM_RSTS first so the firmware comes up into halt mode
 * rather than rebooting. Both paths share the final RSTC write that
 * arms the countdown.
 *
 * Returns 0 on success (the call should never actually return on
 * hardware — the reset fires within ~150 us). Non-zero means we
 * couldn't even map the PM block. */
static int diag_pmReboot(int halt)
{
	void *pm_page;
	volatile uint8_t *pm;

	pm_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, BCM2711_PM_BASE);
	if (pm_page == MAP_FAILED) {
		return -1;
	}
	pm = (volatile uint8_t *)pm_page;

	if (halt) {
		uint32_t rsts = *(volatile uint32_t *)(pm + BCM2711_PM_RSTS);
		*(volatile uint32_t *)(pm + BCM2711_PM_RSTS) =
			PM_PASSWORD | rsts | PM_RSTS_RASPBERRYPI_HALT;
	}

	/* 10 ticks ≈ 150 us, per the bcm2835_wdt driver convention. */
	*(volatile uint32_t *)(pm + BCM2711_PM_WDOG) = PM_PASSWORD | 10u;

	{
		uint32_t rstc = *(volatile uint32_t *)(pm + BCM2711_PM_RSTC);
		*(volatile uint32_t *)(pm + BCM2711_PM_RSTC) =
			PM_PASSWORD | (rstc & PM_RSTC_WRCFG_CLR) |
			PM_RSTC_WRCFG_FULL_RESET;
	}

	/* On hardware the reset fires before we get here. If we somehow
	 * survive (e.g. PM block was inaccessible), surface the error. */
	munmap(pm_page, _PAGE_SIZE);
	return 0;
}


/* Deferred-reboot thread. Spawned by the 'r' / 'h' handlers; sleeps
 * 100 ms to let the UDP reply egress the GENET DMA + wire, then fires
 * the watchdog. */
static uint32_t diag_reboot_stack[1024] __attribute__((aligned(16)));
static volatile int diag_reboot_halt;

static void diag_rebootThread(void *arg)
{
	(void)arg;
	usleep(100 * 1000);
	(void)diag_pmReboot(diag_reboot_halt);
	/* Should never reach here on real hardware. */
	endthread();
}


static int diag_format_reboot(char *buf, size_t cap, int halt)
{
	int off = 0, r;

	r = snprintf(buf + off, cap - off,
		"PHX-DIAG/1 %s\nfiring PM_RSTC countdown in 100ms ...\n.\n",
		halt ? "halt" : "reboot");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	diag_reboot_halt = halt;
	(void)beginthread(diag_rebootThread, 4, diag_reboot_stack,
		sizeof(diag_reboot_stack), NULL);
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
#define VC_PROP_GET_TEMPERATURE 0x00030006u
#define VC_PROP_GET_MAX_TEMP    0x0003000au
#define VC_PROP_GET_THROTTLED   0x00030046u
#define VC_PROP_SET_GPIO_STATE  0x00038041u

#define EXPGPIO_BT_ON           128u  /* expgpio[0] = "BT_ON" per Pi 4 DT */
#define EXPGPIO_WL_ON           129u  /* expgpio[1] = "WL_ON" per Pi 4 DT */

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


/* Generic single-u32-in / single-u32-out mailbox property call.
 * Used for tags like GET_TEMPERATURE (input: sensor_id 0, output: mC),
 * GET_THROTTLED (input: 0, output: throttle bitfield), and
 * GET_MAX_TEMPERATURE (input: sensor_id 0, output: mC). */
static uint32_t diag_mboxProp1in1out(uint32_t tag, uint32_t arg_in)
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

	/* tag layout: [size, REQUEST, tag, valbuf_size=8, req=0, arg_in, out, END]. */
	msg[0] = 32;
	msg[1] = 0;
	msg[2] = tag;
	msg[3] = 8;
	msg[4] = 0;
	msg[5] = arg_in;
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
		result = msg[6];
	}

	munmap(msg_page, _PAGE_SIZE);
	munmap(mbox_page, _PAGE_SIZE);
	return result;
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
	void *sdhci_page;
	uint32_t sdhci_r00 = 0xDEADBEEFu, sdhci_caps_lo = 0xDEADBEEFu;
	uint32_t sdhci_caps_hi = 0xDEADBEEFu, sdhci_version = 0xDEADBEEFu;

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

	/* Thermal + throttle telemetry. Tags expect sensor_id=0 for the
	 * SoC sensor; GET_THROTTLED ignores its arg. */
	{
		uint32_t temp_mc = diag_mboxProp1in1out(VC_PROP_GET_TEMPERATURE, 0);
		uint32_t maxt_mc = diag_mboxProp1in1out(VC_PROP_GET_MAX_TEMP,    0);
		uint32_t throttle = diag_mboxProp1in1out(VC_PROP_GET_THROTTLED,  0);

		r = snprintf(buf + off, cap - off,
			"thermal: temp_mC=%u max_mC=%u throttle=0x%08x"
			"%s%s%s%s%s%s%s%s\n",
			(unsigned)temp_mc, (unsigned)maxt_mc, (unsigned)throttle,
			(throttle & 0x00000001u) ? " uv-now"        : "",
			(throttle & 0x00000002u) ? " arm-cap-now"   : "",
			(throttle & 0x00000004u) ? " throttle-now"  : "",
			(throttle & 0x00000008u) ? " soft-now"      : "",
			(throttle & 0x00010000u) ? " uv-since"      : "",
			(throttle & 0x00020000u) ? " arm-cap-since" : "",
			(throttle & 0x00040000u) ? " throttle-since" : "",
			(throttle & 0x00080000u) ? " soft-since"     : "");
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
	}

	/* Full SDHCI 3.0 register snapshot. The boot-time state lets us
	 * decide what the Tier 1 driver needs to do first (reset?
	 * clock-setup? power-on?). All registers are SDHCI-standard
	 * 32-bit offsets — see Part A2 of the SD Host Controller Simplified
	 * Specification 3.0. */
	sdhci_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, 0xfe300000u);
	if (sdhci_page != MAP_FAILED) {
		volatile uint8_t *base = (volatile uint8_t *)sdhci_page;
		uint32_t pres_state, host_pwr_blkgap, clkctl_to_reset;
		uint32_t int_status, int_status_en, host_ctrl2;

		sdhci_r00       = *(volatile uint32_t *)(base + 0x00);
		pres_state      = *(volatile uint32_t *)(base + 0x24);
		host_pwr_blkgap = *(volatile uint32_t *)(base + 0x28);
		clkctl_to_reset = *(volatile uint32_t *)(base + 0x2c);
		int_status      = *(volatile uint32_t *)(base + 0x30);
		int_status_en   = *(volatile uint32_t *)(base + 0x34);
		sdhci_caps_lo   = *(volatile uint32_t *)(base + 0x40);
		sdhci_caps_hi   = *(volatile uint32_t *)(base + 0x44);
		host_ctrl2      = *(volatile uint32_t *)(base + 0xf8);
		sdhci_version   = *(volatile uint32_t *)(base + 0xfc);
		munmap(sdhci_page, _PAGE_SIZE);

		r = snprintf(buf + off, cap - off,
			"SDHCI@fe300000:\n"
			"  r00=0x%08x  pres=0x%08x  host/pwr=0x%08x  clk/rst=0x%08x\n"
			"  intst=0x%08x  intst_en=0x%08x  caps_lo=0x%08x  caps_hi=0x%08x\n"
			"  hctl2=0x%08x  ver=0x%08x\n",
			(unsigned)sdhci_r00, (unsigned)pres_state,
			(unsigned)host_pwr_blkgap, (unsigned)clkctl_to_reset,
			(unsigned)int_status, (unsigned)int_status_en,
			(unsigned)sdhci_caps_lo, (unsigned)sdhci_caps_hi,
			(unsigned)host_ctrl2, (unsigned)sdhci_version);
	}
	else {
		r = snprintf(buf + off, cap - off, "SDHCI@fe300000: mmap failed\n");
	}
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


/* SDHCI 3.0 register offsets (from the Pi 4 controller at 0xfe300000):
 *   0x00 SDMA_SYSADDR / ARG2 (32-bit)
 *   0x04 BLOCK_SIZE_COUNT (32-bit)
 *   0x08 ARGUMENT_1 (32-bit)
 *   0x0C TRANSFER_MODE (16) + COMMAND (16)
 *   0x10..0x1C RESPONSE_0..3 (32-bit each)
 *   0x20 BUFFER_DATA_PORT (32-bit)
 *   0x24 PRESENT_STATE (32-bit)
 *   0x30 NORMAL_INT_STATUS (16) + ERR_INT_STATUS (16)
 *   0x34 NORMAL_INT_STATUS_EN (16) + ERR_INT_STATUS_EN (16)
 *   0x38 NORMAL_INT_SIGNAL_EN (16) + ERR_INT_SIGNAL_EN (16)
 *
 * Command-register encoding (16-bit at offset 0x0E):
 *   bits 15:8  CMD_NUMBER (0..63)
 *   bits 7:6   CMD_TYPE (00 = normal)
 *   bit  5     DATA_PRESENT
 *   bit  4     CMD_INDEX_CHECK_EN
 *   bit  3     CMD_CRC_CHECK_EN
 *   bits 1:0   RESPONSE_TYPE (00 none, 01 R2 136-bit, 10 R1/3/4/5/6 48-bit, 11 R1b)
 *
 * Issue protocol: poll PRES_STATE.CMD_INHIBIT (bit 0) clear, write
 * ARGUMENT at 0x08, write COMMAND at 0x0E, poll NORMAL_INT_STATUS
 * bit 0 (CMD_COMPLETE), W1C the status, read response. */
#define SDHCI_ARGUMENT_1   0x08u
#define SDHCI_TRANS_CMD    0x0Cu
#define SDHCI_RESPONSE_0   0x10u
#define SDHCI_PRES_STATE   0x24u
#define SDHCI_INT_STATUS   0x30u
#define SDHCI_INT_STAT_EN  0x34u

#define SDHCI_PRES_CMD_INHIBIT  0x00000001u
#define SDHCI_INT_CMD_COMPLETE  0x00000001u
#define SDHCI_INT_ERR_ANY       0x00008000u  /* ERR_INT bits live in the upper 16 */

/* SOFT_RESET_* live in bits 24..26 of the 32-bit dword at offset 0x2C
 * (CLOCK_CTL + TIMEOUT_CTL + SOFT_RESET, big-endian-in-bit-position).
 * Write 1 to the bit to start the reset; the bit clears when done. */
#define SDHCI_CLK_TIMEOUT_RESET 0x2Cu
#define SDHCI_SOFT_RESET_ALL    (1u << 24)
#define SDHCI_SOFT_RESET_CMD    (1u << 25)
#define SDHCI_SOFT_RESET_DAT    (1u << 26)


/* Program SDHCI to a target SD-bus clock by dividing the 250 MHz base.
 * Per SDHCI 3.0 §2.2.13: divisor is 10-bit, output_hz = base / (2*N).
 * For 400 kHz init speed, N = 313 (0x139). 8 low bits go to
 * CLOCK_CTL[15:8], 2 high bits go to CLOCK_CTL[7:6].
 *
 * Bring-up sequence: clear SD_CLOCK_EN, write new FREQ_SELECT, set
 * INTERNAL_CLOCK_EN, wait for INTERNAL_CLOCK_STABLE, set SD_CLOCK_EN. */
static int diag_sdhciSetClockKHz(volatile uint8_t *base, unsigned target_khz)
{
	uint32_t base_hz = 250000000u;
	uint32_t target_hz = (uint32_t)target_khz * 1000u;
	uint32_t divisor;
	uint32_t clkctl;
	uint32_t i;

	if (target_hz == 0u || target_hz > base_hz) {
		return -1;
	}
	divisor = (base_hz + (2u * target_hz) - 1u) / (2u * target_hz);
	if (divisor > 0x3FFu) {
		divisor = 0x3FFu;
	}

	/* Disable SD clock first. The whole dword at 0x2C has CLOCK_CTL
	 * in the low 16, TIMEOUT_CTL+SOFT_RESET in the high 16. RMW the
	 * low 16 only. */
	clkctl = *(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET);
	clkctl &= 0xFFFF0000u;  /* zero CLOCK_CTL */
	*(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET) = clkctl;

	/* Build new CLOCK_CTL:
	 *   bit 0: INTERNAL_CLOCK_EN = 1
	 *   bit 1: stable (read-only, set by HW)
	 *   bit 2: SD_CLOCK_EN = 0 for now
	 *   bits 7:6 = divisor high bits [9:8]
	 *   bits 15:8 = divisor low bits [7:0]
	 */
	{
		uint16_t cctl = (uint16_t)(
			(uint16_t)(divisor & 0xFFu) << 8 |
			(uint16_t)((divisor >> 8) & 0x3u) << 6 |
			(1u << 0));
		uint32_t hi = *(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET) &
			0xFFFF0000u;
		*(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET) =
			hi | (uint32_t)cctl;
	}

	/* Wait for INTERNAL_CLOCK_STABLE (bit 1). */
	for (i = 0; i < 100000u; ++i) {
		uint32_t v = *(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET);
		if ((v & (1u << 1)) != 0u) {
			break;
		}
	}
	if (i == 100000u) {
		return -2;
	}

	/* Enable SD_CLOCK (bit 2). */
	{
		uint32_t v = *(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET);
		v |= (1u << 2);
		*(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET) = v;
	}

	return 0;
}


/* Soft-reset the CMD and DAT lines without disturbing CLOCK_CTL /
 * TIMEOUT_CTL (which firmware has already set up). 32-bit RMW. */
static int diag_sdhciResetCmdDat(volatile uint8_t *base)
{
	uint32_t orig = *(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET);
	uint32_t deadline = 100000u;
	uint32_t i;

	*(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET) =
		(orig & 0x00FFFFFFu) | SDHCI_SOFT_RESET_CMD | SDHCI_SOFT_RESET_DAT;

	for (i = 0; i < deadline; ++i) {
		uint32_t v = *(volatile uint32_t *)(base + SDHCI_CLK_TIMEOUT_RESET);
		if ((v & (SDHCI_SOFT_RESET_CMD | SDHCI_SOFT_RESET_DAT)) == 0u) {
			return 0;
		}
	}
	return -1;
}


/* Issue an SDHCI command. Returns 0 on success, negative on error
 * (CMD_INHIBIT didn't clear, CMD_COMPLETE didn't assert in time,
 * error bits set in INT_STATUS). On success, response_out[0..3] is
 * filled from RESPONSE_0..3 (caller must allocate). */
static int diag_sdhciCmd(volatile uint8_t *base, uint8_t cmd_index,
	uint32_t arg, uint16_t resp_type, uint32_t response_out[4])
{
	uint32_t deadline = 100000u;  /* arbitrary spin count for cmd_inhibit */
	uint32_t i;

	/* Clear stale INT_STATUS bits (W1C). */
	*(volatile uint32_t *)(base + SDHCI_INT_STATUS) = 0xFFFFFFFFu;

	/* Wait for CMD_INHIBIT clear. */
	for (i = 0; i < deadline; ++i) {
		if ((*(volatile uint32_t *)(base + SDHCI_PRES_STATE) &
				SDHCI_PRES_CMD_INHIBIT) == 0u) {
			break;
		}
	}
	if (i == deadline) {
		return -1;  /* CMD_INHIBIT stuck */
	}

	/* Program ARGUMENT then COMMAND. Use 32-bit write to TRANS_CMD
	 * (offset 0x0C): low 16 = TRANSFER_MODE = 0 (no data), high 16 =
	 * COMMAND. The Arasan controller requires the combined 32-bit
	 * write (per Linux sdhci_iproc_writew shadow pattern).
	 *
	 * COMMAND register (offset 0x0E, upper 16 bits of the dword)
	 * layout:
	 *   bits 31:24 (= COMMAND bits 15:8)  CMD_NUMBER
	 *   bits 23:22 (= COMMAND bits 7:6)   CMD_TYPE
	 *   bit  21    (= COMMAND bit 5)      DATA_PRESENT
	 *   bit  20    (= COMMAND bit 4)      CMD_INDEX_CHECK_EN
	 *   bit  19    (= COMMAND bit 3)      CMD_CRC_CHECK_EN
	 *   bits 17:16 (= COMMAND bits 1:0)   RESPONSE_TYPE
	 *
	 * Earlier version stuck resp_type at bits 1:0 of the dword
	 * (which lands in TRANSFER_MODE, NOT COMMAND), so every command
	 * went out with RESPONSE_TYPE=0 (no response). The controller
	 * dutifully asserted CMD_COMPLETE without sampling the bus,
	 * giving the all-zero RESPONSE_0 mystery from the first SDIO
	 * probe attempts. */
	*(volatile uint32_t *)(base + SDHCI_ARGUMENT_1) = arg;
	{
		uint32_t cmd_word =
			((uint32_t)resp_type << 16) |
			((uint32_t)cmd_index << 24);
		*(volatile uint32_t *)(base + SDHCI_TRANS_CMD) = cmd_word;
	}

	/* Wait for CMD_COMPLETE (or any error bit). */
	for (i = 0; i < deadline; ++i) {
		uint32_t st = *(volatile uint32_t *)(base + SDHCI_INT_STATUS);
		if ((st & SDHCI_INT_ERR_ANY) != 0u) {
			return -2;  /* error reported */
		}
		if ((st & SDHCI_INT_CMD_COMPLETE) != 0u) {
			break;
		}
	}
	if (i == deadline) {
		return -3;  /* cmd_complete didn't assert */
	}

	/* Read response registers. */
	if (response_out != NULL) {
		response_out[0] = *(volatile uint32_t *)(base + SDHCI_RESPONSE_0 + 0x0);
		response_out[1] = *(volatile uint32_t *)(base + SDHCI_RESPONSE_0 + 0x4);
		response_out[2] = *(volatile uint32_t *)(base + SDHCI_RESPONSE_0 + 0x8);
		response_out[3] = *(volatile uint32_t *)(base + SDHCI_RESPONSE_0 + 0xC);
	}

	/* W1C the CMD_COMPLETE bit. */
	*(volatile uint32_t *)(base + SDHCI_INT_STATUS) = SDHCI_INT_CMD_COMPLETE;

	return 0;
}


/* WiFi Tier 1c: GPIO 34-39 → ALT3 + WL_REG_ON assertion.
 *
 * Sequence per docs/wifi-bringup-plan.md + the BCM43455 power-on
 * sequence:
 *   1. Set GPFSEL3 to route pins 34-39 to ALT3 (function 7 = SDIO).
 *   2. Call mailbox SET_GPIO_STATE(WL_REG_ON, on) to power on the
 *      WiFi half of the combo chip.
 *   3. Wait ≥150 ms for the chip to settle and pull SD_CLK.
 *   4. Re-read SDHCI registers to see if CAPS populate now that
 *      the chip is alive on the bus. */
static int diag_format_wifi(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	unsigned fsel_before[6] = {0};
	unsigned fsel_after[6] = {0};
	uint32_t pres_before = 0, pres_after = 0;
	uint32_t caps_lo_before = 0, caps_lo_after = 0;
	uint32_t caps_hi_before = 0, caps_hi_after = 0;
	uint32_t wlon_set;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 wifi\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	gpio_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, BCM2711_GPIO_BASE);
	sdhci_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, 0xfe300000u);

	if (gpio_page == MAP_FAILED || sdhci_page == MAP_FAILED) {
		r = snprintf(buf + off, cap - off, "error: mmap failed\n.\n");
		if (gpio_page != MAP_FAILED) {
			munmap(gpio_page, _PAGE_SIZE);
		}
		if (sdhci_page != MAP_FAILED) {
			munmap(sdhci_page, _PAGE_SIZE);
		}
		return off + (r > 0 ? r : 0);
	}

	{
		volatile uint8_t *gpio = (volatile uint8_t *)gpio_page;
		volatile uint8_t *sdhci = (volatile uint8_t *)sdhci_page;
		int i;

		for (i = 0; i < 6; ++i) {
			fsel_before[i] = *(volatile uint32_t *)(gpio + GPIO_GPFSEL0 + i * 4u);
		}
		pres_before    = *(volatile uint32_t *)(sdhci + 0x24);
		caps_lo_before = *(volatile uint32_t *)(sdhci + 0x40);
		caps_hi_before = *(volatile uint32_t *)(sdhci + 0x44);

		/* Step 1: GPIO 34..39 → ALT3 (function 7). */
		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}

		for (i = 0; i < 6; ++i) {
			fsel_after[i] = *(volatile uint32_t *)(gpio + GPIO_GPFSEL0 + i * 4u);
		}

		/* Step 2: WL_REG_ON via mailbox. Reuses the SET_POWER_STATE
		 * helper since both tags share the (device_id, state) packet
		 * layout. */
		wlon_set = diag_mboxPower(VC_PROP_SET_GPIO_STATE,
			EXPGPIO_WL_ON, 1u);

		/* Step 3: wait 150 ms (chip settle per BCM43455 datasheet). */
		usleep(150 * 1000);

		pres_after    = *(volatile uint32_t *)(sdhci + 0x24);
		caps_lo_after = *(volatile uint32_t *)(sdhci + 0x40);
		caps_hi_after = *(volatile uint32_t *)(sdhci + 0x44);
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"GPFSEL3:    before=0x%08x after=0x%08x\n"
		"WL_ON mbox: state_after_set=0x%x\n"
		"SDHCI: pres_before=0x%08x  pres_after=0x%08x\n"
		"SDHCI: caps_lo before=0x%08x after=0x%08x\n"
		"SDHCI: caps_hi before=0x%08x after=0x%08x\n",
		fsel_before[3], fsel_after[3],
		(unsigned)wlon_set,
		(unsigned)pres_before, (unsigned)pres_after,
		(unsigned)caps_lo_before, (unsigned)caps_lo_after,
		(unsigned)caps_hi_before, (unsigned)caps_hi_after);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


/* DCBAA dump: read the Device Context Base Address Array from
 * DRAM via Phoenix's pmap (CPU view). usb-hcd writes this region as
 * cached or coherent DRAM; the VL805 reads it via PCIe bus master
 * DMA. If the CPU view shows valid device-context pointers but the
 * controller HSE's trying to DMA-read the same region, H1 (memory
 * coherence between CPU writes + PCIe DMA reads) is confirmed.
 *
 * usb-hcd allocates DCBAA via dmammap (uncached, MAP_CONTIGUOUS).
 * The PA is stamped into the controller's DCBAAP_LO register — we
 * read 0x032ff000 in cycles 1-5. */
static int diag_format_dcbaa(char *buf, size_t cap)
{
	int off = 0, r;
	void *page;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 dcbaa\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	/* DCBAAP PA from cycles 1-5; could parse from xHCI snapshot but
	 * this is faster for a side experiment. Same dmammap pool so
	 * the PA should be stable across boots (it has been across 5). */
	page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, 0x032ff000u);
	if (page == MAP_FAILED) {
		r = snprintf(buf + off, cap - off, "error: mmap failed\n.\n");
		return off + (r > 0 ? r : 0);
	}

	{
		volatile uint32_t *dcbaa = (volatile uint32_t *)page;
		/* DCBAA entries are 64-bit (low + high u32). Slot 0 is reserved
		 * for the Scratchpad Buffer Array; slots 1..MaxSlotsEn are
		 * device-context pointers. Print first 16 entries. */
		int i;
		for (i = 0; i < 16; ++i) {
			uint32_t lo = dcbaa[i * 2 + 0];
			uint32_t hi = dcbaa[i * 2 + 1];
			r = snprintf(buf + off, cap - off,
				"DCBAA[%2d] = 0x%08x_%08x\n", i,
				(unsigned)hi, (unsigned)lo);
			if (r < 0 || (size_t)r >= cap - off) {
				break;
			}
			off += r;
		}
	}

	munmap(page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


/* USB resumption probe per docs/usb-resumption-strategy.md.
 *
 * Reads xHCI MMIO + USB HCD power state + throttle bits from this
 * (lwip-port) process. This is a side-process inspector — usb-hcd
 * already ran (and probably failed) before lwip started. If the
 * side-process MMIO reads work, H3 ("per-process bridge state
 * applies to reads too") is ruled out and we have a generic xHCI
 * observability channel.
 *
 * Per bcm2711-pcie-0xdead-causes B: VL805 advertises AC64=1 but
 * actually returns garbage on 64-bit reads. EVERY xHCI MMIO read
 * MUST be 32-bit. We split CRCR_HI / DCBAAP_HI etc. into two
 * separate 32-bit loads as per Linux/U-Boot/Circle. */
#define USB_XHCI_MMIO_BASE          0x600000000ull
#define USB_XHCI_MMIO_SIZE          0x1000u  /* VL805 BAR0 is 4 KiB */

#define USB_XHCI_CAP_CAPLENGTH_HCIVER 0x00u
#define USB_XHCI_CAP_HCSPARAMS1     0x04u
#define USB_XHCI_CAP_HCSPARAMS2     0x08u
#define USB_XHCI_CAP_HCSPARAMS3     0x0Cu
#define USB_XHCI_CAP_HCCPARAMS1     0x10u

/* Operational registers; offsets relative to operational base
 * (CAPLENGTH from offset 0x00). */
#define USB_XHCI_OP_USBCMD          0x00u
#define USB_XHCI_OP_USBSTS          0x04u
#define USB_XHCI_OP_PAGESIZE        0x08u
#define USB_XHCI_OP_DNCTRL          0x14u
#define USB_XHCI_OP_CRCR_LO         0x18u
#define USB_XHCI_OP_CRCR_HI         0x1Cu
#define USB_XHCI_OP_DCBAAP_LO       0x30u
#define USB_XHCI_OP_DCBAAP_HI       0x34u
#define USB_XHCI_OP_CONFIG          0x38u

#define VC_DEV_USB_HCD              3u  /* per VC4 mailbox device-id table */


/* USBCMD bit definitions used by the HCRST test. */
#define USB_XHCI_USBCMD_RS       0x00000001u  /* Run/Stop */
#define USB_XHCI_USBCMD_HCRST    0x00000002u  /* Host Controller Reset */
#define USB_XHCI_USBSTS_HCH      0x00000001u  /* Host Controller Halted */
#define USB_XHCI_USBSTS_HSE      0x00000004u  /* Host System Error */
#define USB_XHCI_USBSTS_CNR      0x00000800u  /* Controller Not Ready */


/* USB resumption iteration K: write test from a side process.
 *
 * The previous 10-cycle experiment confirmed side-process MMIO READS
 * work. This probe tests whether side-process MMIO WRITES + the
 * controller's response to them work. Specifically: issue HCRST
 * (USBCMD bit 1), then poll until the bit clears (controller signals
 * reset done) AND USBSTS.CNR clears (controller signals ready).
 *
 * Linux/U-Boot/Circle all issue HCRST as one of the first xhci_init
 * steps after MMIO is mapped. If it works from lwip-port:
 *   - The controller responds to writes from a process other than
 *     the one that did the bridge bring-up.
 *   - The bus-master path may or may not work, but the OS-side
 *     control path is alive.
 *   - usb-hcd's failure becomes more interesting: something it does
 *     between HCRST and R/S=1 (event ring program, CMD ring program,
 *     DCBAA program) is the actual breakage.
 * If HCRST does NOT complete from lwip-port:
 *   - Process-isolation is intact and the wedge is silicon-side. */
static int diag_format_xhci_reset(char *buf, size_t cap)
{
	int off = 0, r;
	void *page;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 xhci-reset\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	page = mmap(NULL, USB_XHCI_MMIO_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, USB_XHCI_MMIO_BASE);
	if (page == MAP_FAILED) {
		r = snprintf(buf + off, cap - off, "error: mmap failed\n.\n");
		return off + (r > 0 ? r : 0);
	}

	{
		volatile uint8_t *base = (volatile uint8_t *)page;
		uint32_t cap_dword = *(volatile uint32_t *)(base + USB_XHCI_CAP_CAPLENGTH_HCIVER);
		uint8_t caplength = (uint8_t)(cap_dword & 0xFFu);

		if (caplength < 0x20u || caplength >= 0x80u) {
			r = snprintf(buf + off, cap - off,
				"abort: CAPLENGTH=0x%02x out of sane range\n.\n",
				caplength);
			munmap(page, USB_XHCI_MMIO_SIZE);
			return off + (r > 0 ? r : 0);
		}

		{
			volatile uint32_t *usbcmd = (volatile uint32_t *)(base + caplength + 0x00);
			volatile uint32_t *usbsts = (volatile uint32_t *)(base + caplength + 0x04);
			uint32_t pre_usbcmd = *usbcmd;
			uint32_t pre_usbsts = *usbsts;
			uint32_t deadline_iters = 1000000u;
			uint32_t i, hcrst_cleared = 0, cnr_cleared = 0;
			uint32_t post_usbcmd, post_usbsts;

			/* Stop the controller first if not already halted. */
			if ((pre_usbsts & USB_XHCI_USBSTS_HCH) == 0u) {
				*usbcmd = pre_usbcmd & ~USB_XHCI_USBCMD_RS;
				for (i = 0; i < deadline_iters; ++i) {
					if ((*usbsts & USB_XHCI_USBSTS_HCH) != 0u) {
						break;
					}
				}
			}

			/* Trigger HCRST. */
			*usbcmd = USB_XHCI_USBCMD_HCRST;

			/* Wait for HCRST bit to clear. */
			for (i = 0; i < deadline_iters; ++i) {
				if ((*usbcmd & USB_XHCI_USBCMD_HCRST) == 0u) {
					hcrst_cleared = i;
					break;
				}
			}

			/* Wait for CNR (Controller Not Ready) to clear. */
			for (i = 0; i < deadline_iters; ++i) {
				if ((*usbsts & USB_XHCI_USBSTS_CNR) == 0u) {
					cnr_cleared = i;
					break;
				}
			}

			post_usbcmd = *usbcmd;
			post_usbsts = *usbsts;

			r = snprintf(buf + off, cap - off,
				"pre  USBCMD=0x%08x  USBSTS=0x%08x\n"
				"HCRST cleared at iter %u%s\n"
				"CNR cleared at iter %u%s\n"
				"post USBCMD=0x%08x  USBSTS=0x%08x\n",
				(unsigned)pre_usbcmd, (unsigned)pre_usbsts,
				(unsigned)hcrst_cleared,
				hcrst_cleared == 0 ? " (already-clear OR timeout)" : "",
				(unsigned)cnr_cleared,
				cnr_cleared == 0 ? " (already-clear OR timeout)" : "",
				(unsigned)post_usbcmd, (unsigned)post_usbsts);
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
	}

	munmap(page, USB_XHCI_MMIO_SIZE);

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


static int diag_format_xhci(char *buf, size_t cap)
{
	int off = 0, r;
	void *page;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 xhci\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	page = mmap(NULL, USB_XHCI_MMIO_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, USB_XHCI_MMIO_BASE);
	if (page == MAP_FAILED) {
		r = snprintf(buf + off, cap - off, "error: mmap failed\n.\n");
		return off + (r > 0 ? r : 0);
	}

	{
		volatile uint8_t *base = (volatile uint8_t *)page;
		uint32_t cap_dword = *(volatile uint32_t *)(base + USB_XHCI_CAP_CAPLENGTH_HCIVER);
		uint8_t caplength = (uint8_t)(cap_dword & 0xFFu);
		uint16_t hciversion = (uint16_t)((cap_dword >> 16) & 0xFFFFu);
		uint32_t hcsp1 = *(volatile uint32_t *)(base + USB_XHCI_CAP_HCSPARAMS1);
		uint32_t hcsp2 = *(volatile uint32_t *)(base + USB_XHCI_CAP_HCSPARAMS2);
		uint32_t hcsp3 = *(volatile uint32_t *)(base + USB_XHCI_CAP_HCSPARAMS3);
		uint32_t hccp1 = *(volatile uint32_t *)(base + USB_XHCI_CAP_HCCPARAMS1);

		r = snprintf(buf + off, cap - off,
			"CAPLENGTH=0x%02x  HCIVERSION=0x%04x\n"
			"HCSPARAMS1=0x%08x  HCSPARAMS2=0x%08x  HCSPARAMS3=0x%08x\n"
			"HCCPARAMS1=0x%08x\n",
			caplength, hciversion,
			(unsigned)hcsp1, (unsigned)hcsp2, (unsigned)hcsp3,
			(unsigned)hccp1);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}

		/* Only read operational registers if CAPLENGTH looks sane.
		 * If the bridge is wedged we may get 0xdeaddead for everything
		 * and CAPLENGTH would be 0xDE; don't follow that into invalid
		 * offsets. */
		if (caplength >= 0x20u && caplength < 0x80u) {
			uint32_t usbcmd  = *(volatile uint32_t *)(base + caplength + USB_XHCI_OP_USBCMD);
			uint32_t usbsts  = *(volatile uint32_t *)(base + caplength + USB_XHCI_OP_USBSTS);
			uint32_t pgsz    = *(volatile uint32_t *)(base + caplength + USB_XHCI_OP_PAGESIZE);
			uint32_t crcr_lo = *(volatile uint32_t *)(base + caplength + USB_XHCI_OP_CRCR_LO);
			uint32_t crcr_hi = *(volatile uint32_t *)(base + caplength + USB_XHCI_OP_CRCR_HI);
			uint32_t dcb_lo  = *(volatile uint32_t *)(base + caplength + USB_XHCI_OP_DCBAAP_LO);
			uint32_t dcb_hi  = *(volatile uint32_t *)(base + caplength + USB_XHCI_OP_DCBAAP_HI);
			uint32_t config  = *(volatile uint32_t *)(base + caplength + USB_XHCI_OP_CONFIG);

			r = snprintf(buf + off, cap - off,
				"USBCMD=0x%08x  USBSTS=0x%08x  PAGESIZE=0x%08x  CONFIG=0x%08x\n"
				"CRCR=0x%08x_%08x  DCBAAP=0x%08x_%08x\n",
				(unsigned)usbcmd, (unsigned)usbsts,
				(unsigned)pgsz, (unsigned)config,
				(unsigned)crcr_hi, (unsigned)crcr_lo,
				(unsigned)dcb_hi, (unsigned)dcb_lo);
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
		else {
			r = snprintf(buf + off, cap - off,
				"operational regs SKIPPED (CAPLENGTH=0x%02x out of sane range — likely 0xdeaddead poison)\n",
				caplength);
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
	}

	munmap(page, USB_XHCI_MMIO_SIZE);

	/* USB HCD power state + throttle bits. */
	{
		uint32_t pwr = diag_mboxPower(VC_PROP_GET_POWER_STATE,
			VC_DEV_USB_HCD, 0u);
		uint32_t throttle = diag_mboxProp1in1out(VC_PROP_GET_THROTTLED, 0);

		r = snprintf(buf + off, cap - off,
			"USB_HCD power: 0x%x   throttle: 0x%08x"
			"%s%s%s%s\n",
			(unsigned)pwr, (unsigned)throttle,
			(throttle & 0x00000001u) ? " uv-now"  : "",
			(throttle & 0x00010000u) ? " uv-since": "",
			(throttle & 0x00000004u) ? " thr-now" : "",
			(throttle & 0x00040000u) ? " thr-since": "");
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


/* SDHCI command-type encodings for the COMMAND register's bits 7:0
 * (in the upper half of the dword at offset 0x0C, so position
 * COMMAND_BITS << 16 in the dword write):
 *
 *   bits 1:0   RESPONSE_TYPE  (0 = none, 1 = R2 136-bit,
 *                              2 = R1/R3/R4/R5/R6/R7 48-bit,
 *                              3 = R1b/R5b 48-bit with busy)
 *   bit  3     CMD_CRC_CHECK_EN
 *   bit  4     CMD_INDEX_CHECK_EN
 *   bit  5     DATA_PRESENT
 *
 *   R0  (no resp)  = 0x00
 *   R1  (CMD7,52)  = 0x1a  (resp=2, CRC, index)
 *   R1b            = 0x1b  (resp=3, CRC, index)
 *   R2             = 0x09  (resp=1, CRC, no index)
 *   R3  (CMD41)    = 0x02  (resp=2, no CRC, no index)
 *   R4  (CMD5)     = 0x02  (resp=2, no CRC, no index)
 *   R5  (CMD52,53) = 0x1a  (resp=2, CRC, index)
 *   R6  (CMD3)     = 0x1a  (resp=2, CRC, index)
 *   R7             = 0x1a  (resp=2, CRC, index)
 */
#define SDHCI_RESP_R0   0x00u
#define SDHCI_RESP_R1   0x1au
#define SDHCI_RESP_R1b  0x1bu
#define SDHCI_RESP_R3   0x02u
#define SDHCI_RESP_R4   0x02u
#define SDHCI_RESP_R5   0x1au
#define SDHCI_RESP_R6   0x1au


/* WiFi Tier 3: SDIO chip enumeration following the standard sequence
 * (post-Tier-2 CMD5 OCR = 0x30ffff00, 3 IO functions, voltage 2.0-3.6V):
 *
 *   CMD5(0)         already done in Tier 2 — ocr returned
 *   CMD5(ocr)       claim the voltage window; poll for C (Ready) bit
 *   CMD3            request RCA
 *   CMD7(rca<<16)   select the card (puts it in CMD state)
 *   CMD52 read F0   read CCCR register 0 (SDIO version)
 *   CMD52 read F0r4 read CIS pointer if SDIO version is sane
 */
static int diag_format_sdio_enum(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t cccr_resp[4] = {0};
	int rc_ocr, rc_claim, rc_rca, rc_sel, rc_cccr;
	int ready_iters = 0;
	uint16_t rca = 0;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-enum\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	gpio_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, BCM2711_GPIO_BASE);
	sdhci_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, 0xfe300000u);

	if (gpio_page == MAP_FAILED || sdhci_page == MAP_FAILED) {
		r = snprintf(buf + off, cap - off, "error: mmap failed\n.\n");
		if (gpio_page != MAP_FAILED) {
			munmap(gpio_page, _PAGE_SIZE);
		}
		if (sdhci_page != MAP_FAILED) {
			munmap(sdhci_page, _PAGE_SIZE);
		}
		return off + (r > 0 ? r : 0);
	}

	{
		volatile uint8_t *gpio = (volatile uint8_t *)gpio_page;
		volatile uint8_t *sdhci = (volatile uint8_t *)sdhci_page;
		int i;

		/* Re-assert Tier 1c power-on (idempotent). */
		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		(void)diag_mboxPower(VC_PROP_SET_GPIO_STATE, EXPGPIO_WL_ON, 1u);
		usleep(150 * 1000);
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		/* CMD0 reset. */
		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);

		/* CMD5 arg=0 — probe OCR. */
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);

		/* CMD5 arg=ocr — claim voltage window. Poll up to 50ms for
		 * the C bit (bit 31 of response) to be set. */
		rc_claim = -1;
		for (ready_iters = 0; ready_iters < 50; ++ready_iters) {
			rc_claim = diag_sdhciCmd(sdhci, 5u, ocr_resp[0] & 0x00ffffffu,
				SDHCI_RESP_R4, claim_resp);
			if (rc_claim != 0) {
				break;
			}
			if ((claim_resp[0] & 0x80000000u) != 0u) {
				ready_iters++;
				break;
			}
			usleep(1000);
		}

		/* CMD3 — get RCA. */
		rc_rca = diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);

		/* CMD7 — select the card. arg = RCA in high 16 bits. */
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		/* CMD52 read F0 reg 0 (SDIO version).
		 * arg layout: [R/W bit31][FN bits30:28][RAW bit27]
		 *             [stuff bit26][reg 17 bits at 25:9][stuff bit8][data 7:0]
		 * Read F0 reg 0 = 0 (everything zero). */
		rc_cccr = diag_sdhciCmd(sdhci, 52u, 0u, SDHCI_RESP_R5, cccr_resp);
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"CMD5(0)    rc=%d  resp=%08x  (OCR + flags)\n"
		"CMD5(ocr)  rc=%d  resp=%08x  ready_iters=%d  C=%d\n"
		"CMD3       rc=%d  resp=%08x  RCA=0x%04x\n"
		"CMD7(rca)  rc=%d  resp=%08x\n"
		"CMD52(F0r0) rc=%d  resp=%08x  (R5: stat/data)\n",
		rc_ocr, (unsigned)ocr_resp[0],
		rc_claim, (unsigned)claim_resp[0], ready_iters,
		(int)((claim_resp[0] >> 31) & 1u),
		rc_rca, (unsigned)rca_resp[0], (unsigned)rca,
		rc_sel, (unsigned)sel_resp[0],
		rc_cccr, (unsigned)cccr_resp[0]);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


/* WiFi Tier 2: full bring-up sequence to CMD0 + CMD5 (SDIO chip
 * discovery). After the Tier 1c power-on, issue:
 *   CMD0  GO_IDLE_STATE       arg=0, no response
 *   CMD5  IO_SEND_OP_COND     arg=0, R4 response = OCR
 * CMD5 is SDIO-specific: SD/MMC cards don't respond to it. A successful
 * CMD5 confirms the BCM43455 SDIO function 0 is alive. */
static int diag_format_sdio(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t pres_pre_wlon, pres_post_wlon, pres_post_cmd0, pres_post_cmd5;
	int rc_cmd0, rc_cmd5;
	uint32_t resp_cmd0[4] = {0}, resp_cmd5[4] = {0};
	uint32_t intst_pre_wlon, intst_post_wlon, intst_post_cmd0, intst_post_cmd5;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	gpio_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, BCM2711_GPIO_BASE);
	sdhci_page = mmap(NULL, _PAGE_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, 0xfe300000u);

	if (gpio_page == MAP_FAILED || sdhci_page == MAP_FAILED) {
		r = snprintf(buf + off, cap - off, "error: mmap failed\n.\n");
		if (gpio_page != MAP_FAILED) {
			munmap(gpio_page, _PAGE_SIZE);
		}
		if (sdhci_page != MAP_FAILED) {
			munmap(sdhci_page, _PAGE_SIZE);
		}
		return off + (r > 0 ? r : 0);
	}

	{
		volatile uint8_t *gpio = (volatile uint8_t *)gpio_page;
		volatile uint8_t *sdhci = (volatile uint8_t *)sdhci_page;
		int i;

		pres_pre_wlon = *(volatile uint32_t *)(sdhci + SDHCI_PRES_STATE);
		intst_pre_wlon = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);

		/* Idempotent re-assert of Tier 1c if not already done. */
		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		(void)diag_mboxPower(VC_PROP_SET_GPIO_STATE, EXPGPIO_WL_ON, 1u);
		usleep(150 * 1000);

		pres_post_wlon = *(volatile uint32_t *)(sdhci + SDHCI_PRES_STATE);
		intst_post_wlon = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);

		/* SDHCI init-speed cap is 400 kHz per SD spec. Firmware left
		 * the clock at ~926 kHz. Some SDIO chips drop responses at
		 * too-high init clocks; program 400 kHz before the first
		 * commands. */
		(void)diag_sdhciSetClockKHz(sdhci, 400u);

		/* Soft-reset CMD + DAT lines to clear stale CMD_INHIBIT. The
		 * BCM2711 controller's PRES_STATE comes up with CMD_INHIBIT=1
		 * after firmware asserts CARD_INSERTED; without this reset
		 * every command spins on the inhibit check. */
		(void)diag_sdhciResetCmdDat(sdhci);

		/* CMD0: GO_IDLE_STATE, no response. */
		rc_cmd0 = diag_sdhciCmd(sdhci, 0u, 0u, 0x0000u, resp_cmd0);
		pres_post_cmd0 = *(volatile uint32_t *)(sdhci + SDHCI_PRES_STATE);
		intst_post_cmd0 = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);

		usleep(2 * 1000);  /* let the chip see CMD0 + settle */

		/* CMD5: IO_SEND_OP_COND, arg=0 (probe), R4 = 48-bit response,
		 * no CRC, no index check. response_type bits 1:0 = 10 = 2 */
		rc_cmd5 = diag_sdhciCmd(sdhci, 5u, 0u, 0x0002u, resp_cmd5);
		pres_post_cmd5 = *(volatile uint32_t *)(sdhci + SDHCI_PRES_STATE);
		intst_post_cmd5 = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"pres pre_wlon=0x%08x intst=0x%08x\n"
		"pres post_wlon=0x%08x intst=0x%08x\n"
		"CMD0  rc=%d  pres=0x%08x intst=0x%08x  resp=%08x %08x %08x %08x\n"
		"CMD5  rc=%d  pres=0x%08x intst=0x%08x  resp=%08x %08x %08x %08x\n",
		(unsigned)pres_pre_wlon,  (unsigned)intst_pre_wlon,
		(unsigned)pres_post_wlon, (unsigned)intst_post_wlon,
		rc_cmd0, (unsigned)pres_post_cmd0, (unsigned)intst_post_cmd0,
		(unsigned)resp_cmd0[0], (unsigned)resp_cmd0[1],
		(unsigned)resp_cmd0[2], (unsigned)resp_cmd0[3],
		rc_cmd5, (unsigned)pres_post_cmd5, (unsigned)intst_post_cmd5,
		(unsigned)resp_cmd5[0], (unsigned)resp_cmd5[1],
		(unsigned)resp_cmd5[2], (unsigned)resp_cmd5[3]);
	if (r > 0 && (size_t)r < cap - off) {
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
	else if (query == 'r') {
		len = diag_format_reboot(body, DIAG_REPLY_MAX, 0);
	}
	else if (query == 'h') {
		len = diag_format_reboot(body, DIAG_REPLY_MAX, 1);
	}
	else if (query == 'g') {
		len = diag_format_gpio(body, DIAG_REPLY_MAX);
	}
	else if (query == 'w') {
		len = diag_format_wifi(body, DIAG_REPLY_MAX);
	}
	else if (query == 'i') {
		len = diag_format_sdio(body, DIAG_REPLY_MAX);
	}
	else if (query == 'x') {
		len = diag_format_xhci(body, DIAG_REPLY_MAX);
	}
	else if (query == 'R') {
		len = diag_format_xhci_reset(body, DIAG_REPLY_MAX);
	}
	else if (query == 'd') {
		len = diag_format_dcbaa(body, DIAG_REPLY_MAX);
	}
	else if (query == 'e') {
		len = diag_format_sdio_enum(body, DIAG_REPLY_MAX);
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
