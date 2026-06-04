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
#include "lwip/dhcp.h"
#include "netif-driver.h"
#include "wifi-fw-43455.h"
#include "wifi-nvram-43455.h"

#include <sys/mman.h>
#include <sys/platform.h>
/* platformctl_t + pctl_graphmode (the VideoCore graphmode query struct); same
 * header pl011-tty's fbcon uses. <sys/platform.h> only declares platformctl(). */
#include <phoenix/arch/aarch64/generic/generic.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/threads.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>


#define DIAG_UDP_PORT 9999u
#define DIAG_REPLY_MAX 1472u  /* max UDP payload in one 1500B Ethernet frame (1500-20-8) */
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
/* 'm' — live memory snapshot of THIS (lwip-port) process and the system page
 * allocator. Used to diagnose the hub_conf OOM: a tiny calloc fails because
 * userspace mmap is eager-backed, so the discriminator is whether physical
 * pages (page_free) are gross-exhausted vs. the per-process map free bytes
 * (maps_free) being depleted/fragmented. page_* are global page-allocator
 * counts; maps_* and entry_* are this process's. */
static int diag_format_meminfo(char *buf, size_t cap)
{
	meminfo_t info;

	memset(&info, 0, sizeof(info));
	info.page.mapsz = -1;
	info.entry.mapsz = -1;
	info.entry.kmapsz = -1;
	info.maps.mapsz = -1;

	meminfo(&info);

	return snprintf(buf, cap,
		"PHX-DIAG/1 meminfo\n"
		"page_alloc: %u\n"
		"page_free: %u\n"
		"page_boot: %u\n"
		"page_sz: %u\n"
		"proc_entries_used: %u\n"
		"proc_entries_total: %u\n"
		"maps_total: %zu\n"
		"maps_free: %zu\n",
		info.page.alloc, info.page.free, info.page.boot, info.page.sz,
		info.entry.total - info.entry.free, info.entry.total,
		info.maps.total, info.maps.free);
}


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


/* BCM2711 PCIe root-complex host register window (0xfd500000). The RC
 * latches the first failing CPU->PCIe (outbound) access in error-status
 * registers at 0x6004..0x6020 (Linux pcie-brcmstb dumps these): a VALID
 * bit, CFG-vs-MEM, read-vs-write, the offending address, and the cause.
 * These latch regardless of whether the CPU SError is masked, so we can
 * read them over UDP after the boot settles to classify the USB-bring-up
 * external-abort SError (see docs/notes/2026-05-29-usb-reanalysis.md). */
#define DIAG_PCIE_RC_BASE 0xfd500000ull
#define DIAG_PCIE_RC_SIZE 0x10000u

/* TODO(#129) USB-enum observability after Step-3 moved USB to a standalone
 * process: the lwip diag responder can no longer read embedded HCD state, and
 * netboot UART captures race the (late, variable-timing) USB enumeration. But
 * the driver-created device nodes are global and resolvable cross-process
 * (#123), so a post-settle UDP 'D' probe statting them is a capture-timing-
 * independent "did USB enumerate the keyboard?" check. present=1 ⇒ usbkbd
 * enumerated the LS keyboard behind the VL805/VIA-hub chain end to end. */
static int diag_format_devnodes(char *buf, size_t cap)
{
	static const char *const nodes[] = { "/dev/kbd0", "/dev/mouse0", "/dev/usb" };
	int off = 0, r;
	unsigned i;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 devnodes\n");
	if (r < 0 || (size_t)r >= (size_t)(cap - off)) {
		return -1;
	}
	off += r;

	for (i = 0u; i < sizeof(nodes) / sizeof(nodes[0]); ++i) {
		struct stat st;
		int present = (stat(nodes[i], &st) == 0) ? 1 : 0;
		r = snprintf(buf + off, cap - off, "%s present=%d errno=%d\n",
			nodes[i], present, present ? 0 : errno);
		if (r < 0 || (size_t)r >= (size_t)(cap - off)) {
			break;
		}
		off += r;
	}
	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < (size_t)(cap - off)) {
		off += r;
	}
	return off;
}


static int diag_format_pcie_err(char *buf, size_t cap)
{
	void *page;
	int off = 0, r;
	static const uint32_t errOffs[] = { 0x6004u, 0x6008u, 0x600cu, 0x6010u, 0x6014u, 0x6018u, 0x601cu, 0x6020u };

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 pcie-err\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	page = mmap(NULL, DIAG_PCIE_RC_SIZE, PROT_READ | PROT_WRITE,
		MAP_DEVICE | MAP_UNCACHED | MAP_PHYSMEM | MAP_ANONYMOUS,
		-1, DIAG_PCIE_RC_BASE);
	if (page == MAP_FAILED) {
		r = snprintf(buf + off, cap - off, "error: RC mmap failed\n.\n");
		return off + (r > 0 ? r : 0);
	}

	{
		volatile uint8_t *base = (volatile uint8_t *)page;
		unsigned k;

		r = snprintf(buf + off, cap - off, "MISC_CTRL=0x%08x MISC_STATUS=0x%08x\n",
			*(volatile uint32_t *)(base + 0x4008u),
			*(volatile uint32_t *)(base + 0x4068u));
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}

		for (k = 0; k < (sizeof(errOffs) / sizeof(errOffs[0])); k++) {
			r = snprintf(buf + off, cap - off, "[0x%04x]=0x%08x\n",
				errOffs[k], *(volatile uint32_t *)(base + errOffs[k]));
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
	}

	munmap(page, DIAG_PCIE_RC_SIZE);
	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
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


/* Cold-power-cycle the BCM43455 WiFi chip via its WL_REG_ON line (a Pi 4
 * expander GPIO driven through the VideoCore mailbox): drop it, wait,
 * re-assert, settle. Centralizes the 4-line toggle that was copy-pasted
 * across every WiFi diag sub-command. NB: a 20x-longer power-down was
 * tested and did NOT make the 43455 firmware execute (the fw-exec gate is
 * not a reset-timing issue — see the bcm43455 memory note); 50/150 ms is
 * the established, enumeration-tested baseline. */
static void diag_wifiPowerCycle(void)
{
	(void)diag_mboxPower(VC_PROP_SET_GPIO_STATE, EXPGPIO_WL_ON, 0u);
	usleep(50 * 1000);
	(void)diag_mboxPower(VC_PROP_SET_GPIO_STATE, EXPGPIO_WL_ON, 1u);
	usleep(150 * 1000);
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
		diag_wifiPowerCycle();
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


/* CMD52 (IO_RW_DIRECT) wrapper. SDIO arg layout:
 *   bit  31    R/W   (1 = write, 0 = read)
 *   bits 30:28 FN    (function number 0..7)
 *   bit  27    RAW   (read-after-write, write-only path)
 *   bit  26    stuff
 *   bits 25:9  REG   (17-bit register address)
 *   bit  8     stuff
 *   bits 7:0   DATA  (write data or stuff for read)
 *
 * Returns diag_sdhciCmd rc; on success, resp_out[0] bits 7:0 contain
 * either the data byte (read) or the echoed write byte. resp_out must
 * be at least a 4-element uint32_t array since diag_sdhciCmd unconditionally
 * dumps all four response slots. */
static int diag_sdioCmd52(volatile uint8_t *sdhci, int write, int fn,
	uint32_t reg, uint8_t data, uint32_t *resp_out)
{
	uint32_t arg = 0;

	arg |= (write ? 1u : 0u) << 31;
	arg |= ((uint32_t)fn & 7u) << 28;
	arg |= ((uint32_t)reg & 0x1ffffu) << 9;
	if (write) {
		arg |= (uint32_t)data;
	}
	return diag_sdhciCmd(sdhci, 52u, arg, SDHCI_RESP_R5, resp_out);
}


/* Switch SDIO to High-Speed (25 MHz) on a 4-bit data bus.
 *
 * Call after the chip is selected and Function 1 is enabled — i.e.
 * after CMD0/5/3/7 + CCCR 0x02 IOEn=2 + IORDY-poll, but BEFORE any
 * CMD53 traffic that wants the higher throughput.
 *
 * Sequence (BCM43455c0 / SDIO 2.0):
 *   1. Read CCCR 0x13 (Bus Speed Select), bit 0 = SHS (Supports HS).
 *      Returns -2 if the chip doesn't claim HS support.
 *   2. Write CCCR 0x13 bit 1 = EHS (Enable High Speed).
 *   3. RMW CCCR 0x07 (Bus Interface Control) bits[1:0] = 0b10 to
 *      select 4-bit data width. Other bits preserved.
 *   4. Set SDHCI Host Control 1 (offset 0x28 byte 0): bit 1 (4BIT)
 *      and bit 2 (HIGH_SPEED) — 32-bit RMW.
 *   5. Re-program SDHCI clock divisor for 25 MHz via
 *      diag_sdhciSetClockKHz().
 *
 * After this the bus runs at ~12.5 MB/s (4 lanes × 25 Mbps),
 * 250× the 400 kHz / 1-bit init speed. */
static int diag_sdioGoHighSpeed(volatile uint8_t *sdhci)
{
	uint32_t hs_resp[4] = {0};
	uint32_t bic_resp[4] = {0};
	int rc;

	rc = diag_sdioCmd52(sdhci, 0, 0, 0x13u, 0u, hs_resp);
	if (rc != 0) {
		return -1;
	}
	if ((hs_resp[0] & 0x01u) == 0u) {
		return -2;  /* SHS not set */
	}

	rc = diag_sdioCmd52(sdhci, 1, 0, 0x13u,
		(uint8_t)((hs_resp[0] | 0x02u) & 0xffu), NULL);
	if (rc != 0) {
		return -3;
	}

	rc = diag_sdioCmd52(sdhci, 0, 0, 0x07u, 0u, bic_resp);
	if (rc != 0) {
		return -4;
	}
	rc = diag_sdioCmd52(sdhci, 1, 0, 0x07u,
		(uint8_t)((bic_resp[0] & 0xFCu) | 0x02u), NULL);
	if (rc != 0) {
		return -5;
	}

	{
		uint32_t hctl = *(volatile uint32_t *)(sdhci + 0x28u);
		hctl &= 0xFFFFFF00u;
		hctl |= (1u << 1) | (1u << 2);
		*(volatile uint32_t *)(sdhci + 0x28u) = hctl;
	}

	rc = diag_sdhciSetClockKHz(sdhci, 25000u);
	if (rc != 0) {
		return -6;
	}
	return 0;
}


/* CMD53 (IO_RW_EXTENDED) block-mode READ via SDHCI PIO.
 *
 * arg layout per SD/SDIO spec:
 *   bit  31    R/W   (0 = read)
 *   bits 30:28 FN
 *   bit  27    block_mode (1)
 *   bit  26    op_code (0 = fixed F1 reg, 1 = incrementing)
 *   bits 25:9  REG   (17-bit F1 register address)
 *   bits 8:0   count (block count if block_mode, byte count otherwise; 0 -> 512)
 *
 * Sets BLOCK_SIZE + BLOCK_COUNT, programs TRANSFER_MODE for read,
 * issues CMD53, polls CMD_COMPLETE, then drains DATA_PORT (offset
 * 0x20) one 32-bit word at a time as BUFFER_READ_READY fires.
 * Waits for TRANSFER_COMPLETE before returning.
 *
 * buf must point to a 4-byte-aligned destination of at least
 * block_count * block_size bytes. */
#define SDHCI_BLOCK_SIZE_CNT  0x04u  /* BLOCK_SIZE (low 16) + BLOCK_COUNT (high 16) */
#define SDHCI_DATA_PORT       0x20u  /* PIO FIFO */
#define SDHCI_INT_XFER_COMPLETE  0x00000002u
#define SDHCI_INT_BUF_RD_READY   0x00000020u

static int diag_sdioCmd53Read(volatile uint8_t *sdhci, int fn,
	int incr_addr, uint32_t reg_addr,
	uint32_t block_count, uint32_t block_size,
	uint8_t *buf)
{
	uint32_t arg, cmd_word;
	uint32_t st;
	uint32_t bytes_total = block_count * block_size;
	uint32_t words_total = bytes_total / 4u;
	uint32_t block_words = block_size / 4u;
	uint32_t bytes_in_block = 0;
	uint32_t i;
	int deadline;

	/* Wait for CMD line idle. */
	for (deadline = 100000; deadline > 0; --deadline) {
		if ((*(volatile uint32_t *)(sdhci + SDHCI_PRES_STATE) &
			SDHCI_PRES_CMD_INHIBIT) == 0u) {
			break;
		}
	}
	if (deadline == 0) {
		return -1;
	}

	/* Clear INT_STATUS so we can poll for fresh CMD_COMPLETE +
	 * BUFFER_READ_READY + TRANSFER_COMPLETE bits. */
	*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xFFFFFFFFu;

	/* Program BLOCK_SIZE + BLOCK_COUNT. */
	*(volatile uint32_t *)(sdhci + SDHCI_BLOCK_SIZE_CNT) =
		(block_count << 16) | (block_size & 0xFFFu);

	/* CMD53 argument. */
	arg = (0u << 31) |
		((uint32_t)(fn & 7u) << 28) |
		(1u << 27) |  /* block_mode */
		((incr_addr ? 1u : 0u) << 26) |
		((reg_addr & 0x1FFFFu) << 9) |
		(block_count & 0x1FFu);
	*(volatile uint32_t *)(sdhci + SDHCI_ARGUMENT_1) = arg;

	/* TRANSFER_MODE (low 16 bits) + COMMAND (upper 16) dword write at
	 * offset 0x0C:
	 *   bit 0  DMA_EN          = 0 (PIO)
	 *   bit 1  BLOCK_COUNT_EN  = 1
	 *   bit 4  DAT_XFER_DIR    = 1 (read)
	 *   bit 5  MULTI_BLK_SEL   = (block_count > 1)
	 *   bits 17:16 RESP_TYPE   = 2 (R1/R5 short response)
	 *   bit 19 CRC_CHECK_EN    = 1
	 *   bit 20 INDEX_CHECK_EN  = 1
	 *   bit 21 DATA_PRESENT    = 1
	 *   bits 31:24 CMD_NUMBER  = 53
	 */
	cmd_word =
		(1u << 1) |
		(1u << 4) |
		((block_count > 1u ? 1u : 0u) << 5) |
		((uint32_t)0x3Au << 16) |
		((uint32_t)53u << 24);
	*(volatile uint32_t *)(sdhci + SDHCI_TRANS_CMD) = cmd_word;

	/* Wait CMD_COMPLETE. */
	for (deadline = 100000; deadline > 0; --deadline) {
		st = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);
		if ((st & SDHCI_INT_ERR_ANY) != 0u) {
			return -2;
		}
		if ((st & SDHCI_INT_CMD_COMPLETE) != 0u) {
			break;
		}
	}
	if (deadline == 0) {
		return -3;
	}
	*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = SDHCI_INT_CMD_COMPLETE;

	/* PIO read loop: drain DATA_PORT one word at a time. After each
	 * block-worth, clear BUFFER_READ_READY and the next block will
	 * (re-)assert it. */
	for (i = 0; i < words_total; ++i) {
		for (deadline = 100000; deadline > 0; --deadline) {
			st = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);
			if ((st & SDHCI_INT_ERR_ANY) != 0u) {
				return -4;
			}
			if ((st & SDHCI_INT_BUF_RD_READY) != 0u) {
				break;
			}
		}
		if (deadline == 0) {
			return -5;
		}

		{
			uint32_t data = *(volatile uint32_t *)(sdhci + SDHCI_DATA_PORT);
			if (buf != NULL) {
				buf[i * 4 + 0] = (uint8_t)(data & 0xffu);
				buf[i * 4 + 1] = (uint8_t)((data >> 8) & 0xffu);
				buf[i * 4 + 2] = (uint8_t)((data >> 16) & 0xffu);
				buf[i * 4 + 3] = (uint8_t)((data >> 24) & 0xffu);
			}
		}

		bytes_in_block += 4u;
		if (bytes_in_block >= block_size) {
			bytes_in_block = 0u;
			*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = SDHCI_INT_BUF_RD_READY;
		}
		(void)block_words;
	}

	/* Wait TRANSFER_COMPLETE. */
	for (deadline = 100000; deadline > 0; --deadline) {
		st = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);
		if ((st & SDHCI_INT_ERR_ANY) != 0u) {
			return -6;
		}
		if ((st & SDHCI_INT_XFER_COMPLETE) != 0u) {
			break;
		}
	}
	if (deadline == 0) {
		return -7;
	}
	*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xFFFFFFFFu;
	return 0;
}


/* CMD53 (IO_RW_EXTENDED) block-mode WRITE via SDHCI PIO.
 *
 * Mirror of diag_sdioCmd53Read. Differences:
 *   - arg bit 31 = 1 (write)
 *   - TRANSFER_MODE bit 4 = 0 (write direction)
 *   - polls BUFFER_WRITE_READY (bit 4 of INT_STATUS) instead of READ_READY
 *   - writes DATA_PORT instead of reading it
 *
 * Source is little-endian byte buffer; each 4 bytes -> one 32-bit
 * DATA_PORT write. buf must be at least block_count * block_size bytes. */
#define SDHCI_INT_BUF_WR_READY   0x00000010u

static int diag_sdioCmd53Write(volatile uint8_t *sdhci, int fn,
	int incr_addr, uint32_t reg_addr,
	uint32_t block_count, uint32_t block_size,
	const uint8_t *buf)
{
	uint32_t arg, cmd_word;
	uint32_t st;
	uint32_t bytes_total = block_count * block_size;
	uint32_t words_total = bytes_total / 4u;
	uint32_t bytes_in_block = 0;
	uint32_t i;
	int deadline;

	for (deadline = 100000; deadline > 0; --deadline) {
		if ((*(volatile uint32_t *)(sdhci + SDHCI_PRES_STATE) &
			SDHCI_PRES_CMD_INHIBIT) == 0u) {
			break;
		}
	}
	if (deadline == 0) {
		return -1;
	}

	*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xFFFFFFFFu;
	*(volatile uint32_t *)(sdhci + SDHCI_BLOCK_SIZE_CNT) =
		(block_count << 16) | (block_size & 0xFFFu);

	/* CMD53 arg with R/W bit 31 = 1 (write). */
	arg = (1u << 31) |
		((uint32_t)(fn & 7u) << 28) |
		(1u << 27) |
		((incr_addr ? 1u : 0u) << 26) |
		((reg_addr & 0x1FFFFu) << 9) |
		(block_count & 0x1FFu);
	*(volatile uint32_t *)(sdhci + SDHCI_ARGUMENT_1) = arg;

	/* TRANSFER_MODE: BLOCK_COUNT_EN, MULTI_BLK if >1; bit 4 DAT_XFER_DIR=0 (write). */
	cmd_word =
		(1u << 1) |
		((block_count > 1u ? 1u : 0u) << 5) |
		((uint32_t)0x3Au << 16) |
		((uint32_t)53u << 24);
	*(volatile uint32_t *)(sdhci + SDHCI_TRANS_CMD) = cmd_word;

	for (deadline = 100000; deadline > 0; --deadline) {
		st = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);
		if ((st & SDHCI_INT_ERR_ANY) != 0u) {
			return -2;
		}
		if ((st & SDHCI_INT_CMD_COMPLETE) != 0u) {
			break;
		}
	}
	if (deadline == 0) {
		return -3;
	}
	*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = SDHCI_INT_CMD_COMPLETE;

	/* PIO write loop. */
	for (i = 0; i < words_total; ++i) {
		for (deadline = 100000; deadline > 0; --deadline) {
			st = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);
			if ((st & SDHCI_INT_ERR_ANY) != 0u) {
				return -4;
			}
			if ((st & SDHCI_INT_BUF_WR_READY) != 0u) {
				break;
			}
		}
		if (deadline == 0) {
			return -5;
		}

		{
			uint32_t data = (uint32_t)buf[i * 4 + 0] |
				((uint32_t)buf[i * 4 + 1] << 8) |
				((uint32_t)buf[i * 4 + 2] << 16) |
				((uint32_t)buf[i * 4 + 3] << 24);
			*(volatile uint32_t *)(sdhci + SDHCI_DATA_PORT) = data;
		}

		bytes_in_block += 4u;
		if (bytes_in_block >= block_size) {
			bytes_in_block = 0u;
			*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = SDHCI_INT_BUF_WR_READY;
		}
	}

	for (deadline = 100000; deadline > 0; --deadline) {
		st = *(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS);
		if ((st & SDHCI_INT_ERR_ANY) != 0u) {
			return -6;
		}
		if ((st & SDHCI_INT_XFER_COMPLETE) != 0u) {
			break;
		}
	}
	if (deadline == 0) {
		return -7;
	}
	*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xFFFFFFFFu;
	return 0;
}


/* WiFi Tier 4: CIS read + Function 1 enable + chip-id readback.
 *
 * After the standard CMD5/3/7 enumeration (same as Tier 3), this:
 *
 *   1. Reads CCCR 0x09/0x0A/0x0B to get the F0 CIS pointer (24-bit LE).
 *   2. Reads the first 8 bytes at the CIS pointer (one CMD52 per byte).
 *      The first tuple should be TPL_MANFID (code 0x20) with vendor
 *      0x02D0 (Broadcom) and device 0xA9BF (BCM43455).
 *   3. Writes CCCR 0x02 IOEn bit 1 to enable Function 1.
 *   4. Polls CCCR 0x03 IORDY bit 1 (up to 50 ms) until set.
 *   5. Programs F1 SBADDRLOW/MID/HIGH (regs 0x1000A/B/C) to point the
 *      32K backplane window at 0x18000000 (ChipCommon core).
 *   6. Reads F1 regs 0x0..0x3 = ChipCommon.chip_id (32-bit LE). The
 *      low 16 bits should be 0x4345 (BCM43455 family). */
static int diag_format_sdio_f1(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t cis_resp[3][4] = {{0}};
	uint32_t cis_byte[8][4] = {{0}};
	uint32_t ioen_pre_resp[4] = {0}, ioen_post_resp[4] = {0};
	uint32_t ioen_set_resp[4] = {0};
	uint32_t iordy_resp[4] = {0};
	uint32_t sbaddr_pre[3][4] = {{0}};
	uint32_t sbaddr_set[3][4] = {{0}};
	uint32_t f1_chipid[4][4] = {{0}};
	int rc_ocr = -1, rc_claim = -1, rc_rca = -1, rc_sel = -1;
	int rc_cis[3] = {-1, -1, -1};
	int rc_cis_body[8] = {-1, -1, -1, -1, -1, -1, -1, -1};
	int rc_ioen_pre = -1, rc_ioen_set = -1, rc_ioen_post = -1;
	int rc_iordy = -1;
	int rc_sbaddr_set[3] = {-1, -1, -1};
	int rc_f1_chipid[4] = {-1, -1, -1, -1};
	int ready_iters = 0, rdy_iters = 0;
	uint16_t rca = 0;
	uint32_t cis_ptr = 0;
	int i;

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-f1\n");
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

		/* Re-assert Tier 1c power-on (idempotent). */
		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		/* SDIO enumeration (same as Tier 3). */
		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		rc_rca = diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		/* Tier 4a: F0 CIS pointer = CCCR 0x09..0x0B (little-endian). */
		rc_cis[0] = diag_sdioCmd52(sdhci, 0, 0, 0x09u, 0u, cis_resp[0]);
		rc_cis[1] = diag_sdioCmd52(sdhci, 0, 0, 0x0Au, 0u, cis_resp[1]);
		rc_cis[2] = diag_sdioCmd52(sdhci, 0, 0, 0x0Bu, 0u, cis_resp[2]);
		cis_ptr = (cis_resp[0][0] & 0xffu) |
			((cis_resp[1][0] & 0xffu) << 8) |
			((cis_resp[2][0] & 0xffu) << 16);

		/* Tier 4b: read first 8 bytes at CIS pointer. */
		if (cis_ptr != 0u) {
			for (i = 0; i < 8; ++i) {
				rc_cis_body[i] = diag_sdioCmd52(sdhci, 0, 0,
					cis_ptr + (uint32_t)i, 0u, cis_byte[i]);
			}
		}

		/* Tier 4c: enable F1 via CCCR 0x02 IOEn bit 1. */
		rc_ioen_pre = diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		rc_ioen_set = diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), ioen_set_resp);
		/* Poll CCCR 0x03 IORDY bit 1 up to 50 ms. */
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}
		rc_ioen_post = diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_post_resp);

		/* Tier 4d: program F1 backplane window to ChipCommon (0x18000000).
		 * SBADDR layout (per Linux brcmfmac / Cypress WHD):
		 *   LOW  (F1 0x1000A) = bit 15 of addr in bit 7 (rest reserved)
		 *   MID  (F1 0x1000B) = bits[23:16] of addr
		 *   HIGH (F1 0x1000C) = bits[31:24] of addr
		 * For 0x18000000: LOW=0x00 MID=0x00 HIGH=0x18. */
		(void)diag_sdioCmd52(sdhci, 0, 1, 0x1000Au, 0u, sbaddr_pre[0]);
		(void)diag_sdioCmd52(sdhci, 0, 1, 0x1000Bu, 0u, sbaddr_pre[1]);
		(void)diag_sdioCmd52(sdhci, 0, 1, 0x1000Cu, 0u, sbaddr_pre[2]);
		rc_sbaddr_set[0] = diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, sbaddr_set[0]);
		rc_sbaddr_set[1] = diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x00u, sbaddr_set[1]);
		rc_sbaddr_set[2] = diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x18u, sbaddr_set[2]);

		/* Tier 4e: read F1 regs 0..3 = ChipCommon.chip_id (32-bit LE). */
		for (i = 0; i < 4; ++i) {
			rc_f1_chipid[i] = diag_sdioCmd52(sdhci, 0, 1,
				(uint32_t)i, 0u, f1_chipid[i]);
		}
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"CMD5(0)    rc=%d  resp=%08x\n"
		"CMD5(ocr)  rc=%d  resp=%08x  ready_iters=%d  C=%d\n"
		"CMD3       rc=%d  resp=%08x  RCA=0x%04x\n"
		"CMD7(rca)  rc=%d  resp=%08x\n",
		rc_ocr, (unsigned)ocr_resp[0],
		rc_claim, (unsigned)claim_resp[0], ready_iters,
		(int)((claim_resp[0] >> 31) & 1u),
		rc_rca, (unsigned)rca_resp[0], (unsigned)rca,
		rc_sel, (unsigned)sel_resp[0]);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"F0 CIS ptr rc=%d/%d/%d  bytes=%02x %02x %02x  -> 0x%06x\n",
		rc_cis[0], rc_cis[1], rc_cis[2],
		(unsigned)(cis_resp[0][0] & 0xff),
		(unsigned)(cis_resp[1][0] & 0xff),
		(unsigned)(cis_resp[2][0] & 0xff),
		(unsigned)cis_ptr);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"CIS[0..7]  %02x %02x %02x %02x %02x %02x %02x %02x  rc=%d/%d/%d/%d/%d/%d/%d/%d\n",
		(unsigned)(cis_byte[0][0] & 0xff), (unsigned)(cis_byte[1][0] & 0xff),
		(unsigned)(cis_byte[2][0] & 0xff), (unsigned)(cis_byte[3][0] & 0xff),
		(unsigned)(cis_byte[4][0] & 0xff), (unsigned)(cis_byte[5][0] & 0xff),
		(unsigned)(cis_byte[6][0] & 0xff), (unsigned)(cis_byte[7][0] & 0xff),
		rc_cis_body[0], rc_cis_body[1], rc_cis_body[2], rc_cis_body[3],
		rc_cis_body[4], rc_cis_body[5], rc_cis_body[6], rc_cis_body[7]);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	if ((cis_byte[0][0] & 0xffu) == 0x20u && (cis_byte[1][0] & 0xffu) >= 4u) {
		uint16_t vendor = (uint16_t)((cis_byte[2][0] & 0xffu) |
			((cis_byte[3][0] & 0xffu) << 8));
		uint16_t device = (uint16_t)((cis_byte[4][0] & 0xffu) |
			((cis_byte[5][0] & 0xffu) << 8));
		r = snprintf(buf + off, cap - off,
			"TPL_MANFID vendor=0x%04x device=0x%04x  %s\n",
			(unsigned)vendor, (unsigned)device,
			(vendor == 0x02D0u && device == 0xA9A6u) ? "(BCM43455)" : "");
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
	}

	r = snprintf(buf + off, cap - off,
		"F1 IOEn pre rc=%d val=0x%02x  set rc=%d  IORDY rc=%d iters=%d val=0x%02x  IOEn post rc=%d val=0x%02x\n",
		rc_ioen_pre, (unsigned)(ioen_pre_resp[0] & 0xff),
		rc_ioen_set, rc_iordy, rdy_iters,
		(unsigned)(iordy_resp[0] & 0xff),
		rc_ioen_post, (unsigned)(ioen_post_resp[0] & 0xff));
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"F1 SBADDR pre L=%02x M=%02x H=%02x  set rc=%d/%d/%d -> L=00 M=00 H=18\n",
		(unsigned)(sbaddr_pre[0][0] & 0xff),
		(unsigned)(sbaddr_pre[1][0] & 0xff),
		(unsigned)(sbaddr_pre[2][0] & 0xff),
		rc_sbaddr_set[0], rc_sbaddr_set[1], rc_sbaddr_set[2]);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	{
		uint32_t cid = (f1_chipid[0][0] & 0xffu) |
			((f1_chipid[1][0] & 0xffu) << 8) |
			((f1_chipid[2][0] & 0xffu) << 16) |
			((f1_chipid[3][0] & 0xffu) << 24);
		r = snprintf(buf + off, cap - off,
			"F1 backplane[0..3] rc=%d/%d/%d/%d  %02x %02x %02x %02x  chipid=0x%08x  %s\n",
			rc_f1_chipid[0], rc_f1_chipid[1], rc_f1_chipid[2], rc_f1_chipid[3],
			(unsigned)(f1_chipid[0][0] & 0xff), (unsigned)(f1_chipid[1][0] & 0xff),
			(unsigned)(f1_chipid[2][0] & 0xff), (unsigned)(f1_chipid[3][0] & 0xff),
			(unsigned)cid,
			((cid & 0xffffu) == 0x4345u) ? "(chip=0x4345 BCM43455)" : "");
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


/* WiFi P3 prep: deep F1 backplane probe.
 *
 * After the standard SDIO enumeration + F1 enable, this:
 *
 *   1. Runs an F1 SBADDR write round-trip: write H=0x19 (window
 *      points at 0x19000000, unused address space), read back,
 *      write H=0x18 (back to ChipCommon window), read back.
 *      Validates CMD52 writes to F1 register space succeed.
 *
 *   2. Walks 8 backplane offsets (4 KB stride) within the 32 KB
 *      window starting at 0x18000000 — ChipCommon, +0x1000,
 *      +0x2000, ... +0x7000. Each probe is 4 CMD52 reads
 *      forming a 32-bit word from the bus's perspective.
 *
 * Output is the raw first word at each offset. 0xFFFFFFFF means
 * "no core wired at that backplane address" (bus error returns
 * all-ones); anything else is a component-id-or-control register
 * for a real core. The pattern across the 8 probes is a fingerprint
 * of the chip's wrapper-block layout. */
static int diag_format_sdio_cores(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	uint32_t sbaddr_h_after_w1[4] = {0}, sbaddr_h_after_w2[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1;
	int rc_iordy = -1;
	int rc_sbaddr_w1 = -1, rc_sbaddr_r1 = -1;
	int rc_sbaddr_w2 = -1, rc_sbaddr_r2 = -1;
	int ready_iters = 0, rdy_iters = 0;
	uint16_t rca = 0;
	int i, j;

	enum { N_PROBES = 8 };
	static const uint32_t probe_offsets[N_PROBES] = {
		0x0000u, 0x1000u, 0x2000u, 0x3000u,
		0x4000u, 0x5000u, 0x6000u, 0x7000u
	};
	uint32_t probe_resp[N_PROBES][4][4];
	int rc_probe[N_PROBES][4];

	/* EROM pointer (ChipCommon offset 0xFC) and first EROM entry. */
	uint32_t eromptr_resp[4][4] = {{0}};
	int rc_eromptr[4] = {-1, -1, -1, -1};
	uint32_t erom_entry0_resp[4][4] = {{0}};
	int rc_erom_entry0[4] = {-1, -1, -1, -1};
	uint32_t erom_ptr = 0;

	memset(probe_resp, 0, sizeof(probe_resp));
	for (i = 0; i < N_PROBES; ++i) {
		for (j = 0; j < 4; ++j) {
			rc_probe[i][j] = -1;
		}
	}

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-cores\n");
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

		/* Re-assert Tier 1c power-on (idempotent). */
		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		/* SDIO enumeration (same as Tier 3). */
		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		/* Enable F1 (same as 'f'). */
		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		/* F1 SBADDR write round-trip: H=0x19 then back to H=0x18. */
		rc_sbaddr_w1 = diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x19u, NULL);
		rc_sbaddr_r1 = diag_sdioCmd52(sdhci, 0, 1, 0x1000Cu, 0u, sbaddr_h_after_w1);
		rc_sbaddr_w2 = diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x18u, NULL);
		rc_sbaddr_r2 = diag_sdioCmd52(sdhci, 0, 1, 0x1000Cu, 0u, sbaddr_h_after_w2);

		/* Belt-and-suspenders: re-program L=0, M=0 explicitly before
		 * any further F1 reads so window alignment is unambiguous. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x00u, NULL);

		/* Read ChipCommon[0xFC..0xFF] = EROM pointer FIRST, while the
		 * SDHCI host is in a clean state. The probe loop below
		 * deliberately exercises unmapped backplane addresses and
		 * accumulates SDHCI error state that's hard to fully recover
		 * from, so reading important registers up-front avoids cascade
		 * failures masking the EROM value. */
		for (j = 0; j < 4; ++j) {
			rc_eromptr[j] = diag_sdioCmd52(sdhci, 0, 1,
				0xFCu + (uint32_t)j, 0u, eromptr_resp[j]);
			if (rc_eromptr[j] != 0) {
				*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xffffffffu;
				(void)diag_sdhciResetCmdDat(sdhci);
				break;
			}
		}
		erom_ptr = (eromptr_resp[0][0] & 0xffu) |
			((eromptr_resp[1][0] & 0xffu) << 8) |
			((eromptr_resp[2][0] & 0xffu) << 16) |
			((eromptr_resp[3][0] & 0xffu) << 24);

		/* If EROMPTR looks like a backplane address, read first
		 * 4-byte entry from EROM (also in clean state). */
		if ((erom_ptr & 0xff000000u) == 0x18000000u) {
			uint32_t erom_lo = (uint8_t)((erom_ptr >> 15) & 0x1u) << 7;
			uint32_t erom_mid = (uint8_t)((erom_ptr >> 16) & 0xffu);
			uint32_t erom_hi = (uint8_t)((erom_ptr >> 24) & 0xffu);
			uint32_t erom_win_off = erom_ptr & 0x7fffu;

			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, (uint8_t)erom_lo, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, (uint8_t)erom_mid, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, (uint8_t)erom_hi, NULL);

			for (j = 0; j < 4; ++j) {
				rc_erom_entry0[j] = diag_sdioCmd52(sdhci, 0, 1,
					erom_win_off + (uint32_t)j, 0u, erom_entry0_resp[j]);
				if (rc_erom_entry0[j] != 0) {
					*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xffffffffu;
					(void)diag_sdhciResetCmdDat(sdhci);
					break;
				}
			}

			/* Restore window back to ChipCommon (0x18000000) for the
			 * subsequent probe loop. */
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x00u, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x18u, NULL);
		}

		/* Walk 8 backplane offsets inside the 32 KB window. Each probe
		 * is byte-wise (4 CMD52 reads). Backplane addresses pointing
		 * at unmapped wrapper blocks raise an SDHCI CMD-line error
		 * (timeout/CRC); to avoid cascade failure that masks later
		 * probes, clear INT_STATUS error bits and reset the CMD line
		 * after any failed transfer before moving on. */
		for (i = 0; i < N_PROBES; ++i) {
			uint32_t off_base = probe_offsets[i];
			for (j = 0; j < 4; ++j) {
				rc_probe[i][j] = diag_sdioCmd52(sdhci, 0, 1,
					off_base + (uint32_t)j, 0u, probe_resp[i][j]);
				if (rc_probe[i][j] != 0) {
					*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xffffffffu;
					(void)diag_sdhciResetCmdDat(sdhci);
					break;
				}
			}
		}
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5(0) rc=%d, CMD5(ocr) rc=%d C=%d, CMD3 RCA=0x%04x, CMD7 rc=%d, F1 IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"F1 SBADDR-H write-trip:  0x19 rc=%d  read=0x%02x (rc=%d)  0x18 rc=%d  read=0x%02x (rc=%d)\n",
		rc_sbaddr_w1, (unsigned)(sbaddr_h_after_w1[0] & 0xff), rc_sbaddr_r1,
		rc_sbaddr_w2, (unsigned)(sbaddr_h_after_w2[0] & 0xff), rc_sbaddr_r2);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	for (i = 0; i < N_PROBES; ++i) {
		uint32_t bp_addr = 0x18000000u + probe_offsets[i];
		uint32_t word = (probe_resp[i][0][0] & 0xffu) |
			((probe_resp[i][1][0] & 0xffu) << 8) |
			((probe_resp[i][2][0] & 0xffu) << 16) |
			((probe_resp[i][3][0] & 0xffu) << 24);
		r = snprintf(buf + off, cap - off,
			"@0x%08x rc=%d/%d/%d/%d  %02x %02x %02x %02x  word=0x%08x\n",
			(unsigned)bp_addr,
			rc_probe[i][0], rc_probe[i][1], rc_probe[i][2], rc_probe[i][3],
			(unsigned)(probe_resp[i][0][0] & 0xff),
			(unsigned)(probe_resp[i][1][0] & 0xff),
			(unsigned)(probe_resp[i][2][0] & 0xff),
			(unsigned)(probe_resp[i][3][0] & 0xff),
			(unsigned)word);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
	}

	r = snprintf(buf + off, cap - off,
		"EROMPTR @0xFC rc=%d/%d/%d/%d  %02x %02x %02x %02x  -> 0x%08x\n",
		rc_eromptr[0], rc_eromptr[1], rc_eromptr[2], rc_eromptr[3],
		(unsigned)(eromptr_resp[0][0] & 0xff),
		(unsigned)(eromptr_resp[1][0] & 0xff),
		(unsigned)(eromptr_resp[2][0] & 0xff),
		(unsigned)(eromptr_resp[3][0] & 0xff),
		(unsigned)erom_ptr);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	if ((erom_ptr & 0xff000000u) == 0x18000000u) {
		uint32_t entry = (erom_entry0_resp[0][0] & 0xffu) |
			((erom_entry0_resp[1][0] & 0xffu) << 8) |
			((erom_entry0_resp[2][0] & 0xffu) << 16) |
			((erom_entry0_resp[3][0] & 0xffu) << 24);
		const char *etype_str;
		switch (entry & 0x3u) {
			case 0: etype_str = "end"; break;
			case 1: etype_str = "CompIdent"; break;
			case 5: etype_str = "AddrDesc"; break;
			default: etype_str = "misc"; break;
		}
		r = snprintf(buf + off, cap - off,
			"EROM[0] @0x%08x rc=%d/%d/%d/%d  word=0x%08x  type=%s",
			(unsigned)erom_ptr,
			rc_erom_entry0[0], rc_erom_entry0[1], rc_erom_entry0[2], rc_erom_entry0[3],
			(unsigned)entry, etype_str);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		if ((entry & 0x3u) == 1u) {
			/* CompIdent entry layout (Broadcom EROM):
			 *   bits[31:20] = Designer (0x4bf = Broadcom)
			 *   bits[19:8]  = PartNumber (component ID, e.g. 0x800 = CC)
			 *   bits[7:4]   = ClassCode
			 *   bits[3:2]   = NumSlavePorts / NumMasters
			 *   bits[1:0]   = 1 (CompIdent)
			 */
			r = snprintf(buf + off, cap - off,
				"  Designer=0x%03x PartNum=0x%03x",
				(unsigned)((entry >> 20) & 0xfffu),
				(unsigned)((entry >> 8) & 0xfffu));
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
		r = snprintf(buf + off, cap - off, "\n");
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


/* WiFi P3 prep: walk first 16 EROM entries to enumerate cores.
 *
 * The EROM (Enumeration ROM) table at backplane address
 * ChipCommon[0xFC] contains one 4-byte entry per attribute of every
 * core in the chip:
 *   - CompIdent (type=1): identifies a core (Designer + PartNumber).
 *   - AddrDesc  (type=5): one or more follow, giving the core's
 *     backplane base address(es) + size encoding.
 *   - end       (type=0): table terminator.
 *   - misc      (type=6/7): wrapper / per-port descriptors.
 *
 * For BCM43455 the table is ~80 bytes (20 entries); 16 entries is
 * usually enough to reach the SDIO + ARM-CR4 + SOCRAM cores, the
 * three the P3 firmware-download path will need to address.
 *
 * 64 bytes of EROM fits inside a single 32KB SBADDR window, so we
 * program the window once and walk via F1-reg-offset reads. */
static int diag_format_sdio_erom(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	uint32_t eromptr_resp[4][4] = {{0}};
	int rc_eromptr[4] = {-1, -1, -1, -1};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int ready_iters = 0, rdy_iters = 0;
	uint16_t rca = 0;
	uint32_t erom_ptr = 0;
	int i, j;

	enum { N_ENTRIES = 40 };
	uint32_t entries[N_ENTRIES] = {0};
	int rc_entry[N_ENTRIES] = {0};
	uint32_t entry_resp[N_ENTRIES][4][4];

	memset(entry_resp, 0, sizeof(entry_resp));
	for (i = 0; i < N_ENTRIES; ++i) {
		rc_entry[i] = -1;
	}

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-erom\n");
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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		/* Window is at 0x18000000 by default. Read CC[0xFC..0xFF] =
		 * EROM pointer. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x18u, NULL);
		for (j = 0; j < 4; ++j) {
			rc_eromptr[j] = diag_sdioCmd52(sdhci, 0, 1,
				0xFCu + (uint32_t)j, 0u, eromptr_resp[j]);
		}
		erom_ptr = (eromptr_resp[0][0] & 0xffu) |
			((eromptr_resp[1][0] & 0xffu) << 8) |
			((eromptr_resp[2][0] & 0xffu) << 16) |
			((eromptr_resp[3][0] & 0xffu) << 24);

		/* Move SBADDR window to align with EROM page. Window is
		 * 32KB-aligned; offset within window = erom_ptr & 0x7FFF. */
		if ((erom_ptr & 0xff000000u) == 0x18000000u) {
			uint32_t erom_lo = (uint8_t)((erom_ptr >> 15) & 0x1u) << 7;
			uint32_t erom_mid = (uint8_t)((erom_ptr >> 16) & 0xffu);
			uint32_t erom_hi = (uint8_t)((erom_ptr >> 24) & 0xffu);
			uint32_t erom_win_off = erom_ptr & 0x7fffu;

			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, (uint8_t)erom_lo, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, (uint8_t)erom_mid, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, (uint8_t)erom_hi, NULL);

			/* Walk 16 entries × 4 bytes each = 64 CMD52 reads. If
			 * any byte read errors, recover SDHCI state and continue
			 * with the next entry. */
			for (i = 0; i < N_ENTRIES; ++i) {
				int entry_ok = 1;
				for (j = 0; j < 4; ++j) {
					uint32_t reg = erom_win_off + (uint32_t)(i * 4 + j);
					int rc = diag_sdioCmd52(sdhci, 0, 1, reg, 0u, entry_resp[i][j]);
					if (rc != 0) {
						entry_ok = 0;
						*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xffffffffu;
						(void)diag_sdhciResetCmdDat(sdhci);
						break;
					}
				}
				if (entry_ok) {
					entries[i] = (entry_resp[i][0][0] & 0xffu) |
						((entry_resp[i][1][0] & 0xffu) << 8) |
						((entry_resp[i][2][0] & 0xffu) << 16) |
						((entry_resp[i][3][0] & 0xffu) << 24);
					rc_entry[i] = 0;
				}
			}
		}
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=0/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d  EROMPTR=0x%08x\n",
		rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters,
		(unsigned)erom_ptr);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_ocr;
	(void)rc_iordy;
	(void)rc_eromptr;

	/* EROM entry type field is bits[3:0] (4-bit), not bits[1:0]:
	 *   0x0 EMPTY     — skip
	 *   0x1 COMP      — component descriptor (followed by another
	 *                   type=1 second word, then MASTER_PORT/ADDRESS)
	 *   0x3 MASTER_PORT
	 *   0x5 ADDRESS   — slave wrapper backplane address
	 *   0x7 ADDRESS_EXT
	 *   0xF EOT       — end of table
	 * Walk continues past EMPTY; terminates on EOT. */
	for (i = 0; i < N_ENTRIES; ++i) {
		uint32_t e = entries[i];
		uint32_t type4 = e & 0xfu;
		if (rc_entry[i] != 0) {
			r = snprintf(buf + off, cap - off,
				"[%02d] @0x%08x rc=%d\n",
				i, (unsigned)(erom_ptr + (uint32_t)(i * 4)),
				rc_entry[i]);
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
			continue;
		}
		if (type4 == 0xfu || e == 0xFFFFFFFFu) {
			r = snprintf(buf + off, cap - off,
				"[%02d] 0x%08x  EOT\n", i, (unsigned)e);
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
			break;
		}
		if (type4 == 0x1u) {
			r = snprintf(buf + off, cap - off,
				"[%02d] c %03x/%03x\n",
				i,
				(unsigned)((e >> 20) & 0xfffu),
				(unsigned)((e >> 8) & 0xfffu));
		}
		else if (type4 == 0x3u) {
			r = snprintf(buf + off, cap - off, "[%02d] mp\n", i);
		}
		else if (type4 == 0x5u || type4 == 0x7u) {
			r = snprintf(buf + off, cap - off,
				"[%02d] a 0x%08x\n",
				i, (unsigned)(e & 0xfffff000u));
		}
		else if (type4 == 0x0u) {
			r = snprintf(buf + off, cap - off, "[%02d] -\n", i);
		}
		else {
			r = snprintf(buf + off, cap - off,
				"[%02d] t=%x 0x%08x\n",
				i, (unsigned)type4, (unsigned)e);
		}
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


/* WiFi P3 prep: read ARM-CR4 control region.
 *
 * From the 40-entry EROM walk: BCM43455's ARM-CR4 has TWO logical
 * regions in the backplane:
 *
 *   0x18002000  ARM-CR4 main port (Part 0x83E)
 *   0x18003000  ARM-CR4 control region (Part 0x83C) — this is what
 *               brcmfmac calls "armcore_base", where ResetCtrl and
 *               IoCtrl live. ResetCtrl bit 0 = hold-in-reset.
 *
 * This sub-command moves the F1 SBADDR window onto 0x18003000 and
 * READS:
 *
 *   F1 reg 0x408 = IoCtrl     (ARM ioctl bits, including clk_en)
 *   F1 reg 0x800 = ResetCtrl  (bit 0 = ARM held in reset)
 *
 * Read-only. Writing ResetCtrl=0 (release ARM) here would jump the
 * CR4 into uninitialized SOCRAM — that step belongs to the P3
 * firmware-download driver, not the diagnostic probe.
 *
 * Expected first-cycle value: ResetCtrl = 0x1 (in reset) since the
 * Pi 4 boots with the chip's CR4 not yet released by any host
 * driver. */
static int diag_format_sdio_arm(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int ready_iters = 0, rdy_iters = 0;
	uint16_t rca = 0;

	/* The previous attempt at 0x18003000 / 0x18005000 (cores' main
	 * ports in the 0x18000000 window) all failed rc=-2. Per EROM
	 * walk, each core also has a "wrapper" address in the
	 * 0x18100000 page:
	 *   ChipCommon (CC)   main 0x18000000  wrapper 0x18100000
	 *   D11 MAC           main 0x18001000  wrapper 0x18101000
	 *   ARM-CR4 (0x83E)   main 0x18002000  wrapper 0x18102000
	 *   0x83C             main 0x18003000  wrapper 0x18103000
	 * The wrapper region is where AXI-bus ResetCtrl + IoCtrl live
	 * per standard Broadcom siutils. Probe both ARM-CR4 wrapper
	 * (0x18102000) and 0x83C wrapper (0x18103000) at standard
	 * offsets +0x0 / +0x408 / +0x800. Window programmed to
	 * 0x18100000 first (SBADDR L=0x00 M=0x10 H=0x18). */
	enum { N_PROBES = 6 };
	static const uint32_t probe_offs[N_PROBES] = {
		0x2000u, 0x2408u, 0x2800u,
		0x3000u, 0x3408u, 0x3800u };
	static const char *probe_names[N_PROBES] = {
		"0x18102000+0x000 (0x83E wrap)",
		"0x18102000+0x408 IoCtrl",
		"0x18102000+0x800 ResetCtrl",
		"0x18103000+0x000 (0x83C wrap)",
		"0x18103000+0x408 IoCtrl",
		"0x18103000+0x800 ResetCtrl" };
	uint32_t probe_words[N_PROBES] = {0};
	int probe_rc[N_PROBES] = { -1, -1, -1, -1, -1, -1 };
	uint32_t pw[N_PROBES][4][4];
	int p, j;
	memset(pw, 0, sizeof(pw));

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-arm\n");
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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		/* Window to 0x18100000 (wrappers page). F1 reg 0x2000 maps
		 * to backplane 0x18102000 (ARM-CR4 wrapper), F1 reg 0x3000
		 * maps to 0x18103000 (0x83C wrapper). */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x10u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x18u, NULL);

		for (p = 0; p < N_PROBES; ++p) {
			int probe_ok = 1;
			for (j = 0; j < 4; ++j) {
				int rc = diag_sdioCmd52(sdhci, 0, 1,
					probe_offs[p] + (uint32_t)j, 0u, pw[p][j]);
				if (rc != 0) {
					probe_ok = 0;
					probe_rc[p] = rc;
					*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xffffffffu;
					(void)diag_sdhciResetCmdDat(sdhci);
					break;
				}
			}
			if (probe_ok) {
				probe_rc[p] = 0;
				probe_words[p] = (pw[p][0][0] & 0xffu) |
					((pw[p][1][0] & 0xffu) << 8) |
					((pw[p][2][0] & 0xffu) << 16) |
					((pw[p][3][0] & 0xffu) << 24);
			}
		}
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=%d/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_iordy;

	for (p = 0; p < N_PROBES; ++p) {
		r = snprintf(buf + off, cap - off,
			"%s rc=%d word=0x%08x\n",
			probe_names[p], probe_rc[p], (unsigned)probe_words[p]);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
	}
	if (probe_rc[2] == 0) {
		r = snprintf(buf + off, cap - off,
			"  -> 0x83E (ARM-CR4) @0x18102800 ResetCtrl bit0 = %u  %s\n",
			(unsigned)(probe_words[2] & 0x1u),
			(probe_words[2] & 0x1u) ? "(held in reset)" : "(released)");
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
	}
	if (probe_rc[5] == 0) {
		r = snprintf(buf + off, cap - off,
			"  -> 0x83C (brcmfmac armcore) @0x18103800 ResetCtrl bit0 = %u  %s\n",
			(unsigned)(probe_words[5] & 0x1u),
			(probe_words[5] & 0x1u) ? "(HELD IN RESET, ready for firmware-release)" : "(released)");
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


/* WiFi P3 prep: read SOCRAM + BootROM via SBADDR window relocation
 * to the chip's INTERNAL address space.
 *
 * The 0x18000000-base addresses we've used so far are BCM43455
 * backplane-bus addresses for cores. To reach chip-internal ROM /
 * SRAM (where firmware code+data live), the SBADDR window can be
 * pointed at *chip-internal* addresses 0x00000000..0x07FFFFFF, where:
 *
 *   0x00000000  BootROM start (ARM-CR4 vector table on POR)
 *   0x00198000  SOCRAM start (per brcmfmac rambase for 43455)
 *   ~0x00258000 SOCRAM end (rambase + 0xC0000 = 768 KB)
 *
 * Each 32 KB window read sees a 32 KB slice of the chip-internal
 * memory map. P3 firmware download walks SBADDR through the SOCRAM
 * range, writing the brcmfmac43455-sdio.bin payload via CMD53 block
 * writes.
 *
 * This probe READS the first 4 bytes at:
 *   0x00000000  BootROM   (expect ARM exception vector or magic)
 *   0x00198000  SOCRAM    (POR: undefined, often zero)
 *
 * Validates window relocation to chip-internal address space and
 * gives a first look at what's actually in the chip's memory. */
static int diag_format_sdio_socram(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int ready_iters = 0, rdy_iters = 0;
	uint16_t rca = 0;

	enum { N_TARGETS = 2, DUMP_WORDS = 8 };
	static const uint32_t target_addr[N_TARGETS] = {
		0x00000000u,
		0x00198000u
	};
	static const char *target_name[N_TARGETS] = {
		"BootROM @0x00000000",
		"SOCRAM  @0x00198000 (brcmfmac rambase)"
	};
	uint32_t target_words[N_TARGETS][DUMP_WORDS];
	int target_rc[N_TARGETS] = { -1, -1 };
	uint32_t resp_buf[4];
	int t, w, j;

	memset(target_words, 0, sizeof(target_words));

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-socram\n");
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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		/* For each target, set SBADDR and read DUMP_WORDS words
		 * (32 bytes) at the in-window offset. */
		for (t = 0; t < N_TARGETS; ++t) {
			uint32_t addr = target_addr[t];
			uint8_t sb_lo = (uint8_t)(((addr >> 15) & 0x1u) << 7);
			uint8_t sb_mid = (uint8_t)((addr >> 16) & 0xffu);
			uint8_t sb_hi = (uint8_t)((addr >> 24) & 0xffu);
			uint32_t win_off = addr & 0x7fffu;
			int probe_ok = 1;

			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, sb_lo, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, sb_mid, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, sb_hi, NULL);

			for (w = 0; w < DUMP_WORDS; ++w) {
				uint32_t word_off = win_off + (uint32_t)(w * 4);
				int word_ok = 1;
				for (j = 0; j < 4; ++j) {
					int rc = diag_sdioCmd52(sdhci, 0, 1,
						word_off + (uint32_t)j, 0u, resp_buf);
					if (rc != 0) {
						word_ok = 0;
						probe_ok = 0;
						*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS) = 0xffffffffu;
						(void)diag_sdhciResetCmdDat(sdhci);
						break;
					}
					target_words[t][w] |= (resp_buf[0] & 0xffu) << (j * 8);
				}
				if (!word_ok) {
					break;
				}
			}
			target_rc[t] = probe_ok ? 0 : -2;
		}
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=%d/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_iordy;

	for (t = 0; t < N_TARGETS; ++t) {
		r = snprintf(buf + off, cap - off,
			"%s  rc=%d\n", target_name[t], target_rc[t]);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		for (w = 0; w < DUMP_WORDS; ++w) {
			r = snprintf(buf + off, cap - off,
				"  +0x%02x  0x%08x\n",
				(unsigned)(w * 4), (unsigned)target_words[t][w]);
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
	}

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


/* WiFi P3: CMD53 block-mode read smoke test.
 *
 * After SDIO + F1 enable + SBADDR=0x18000000, issues a single-block
 * CMD53 IO_RW_EXTENDED read of 64 bytes starting at F1 reg 0
 * (= backplane 0x18000000, ChipCommon). Compares the first 4 bytes
 * against the known CMD52 chip-id value (0x45 0x43 0x26 0x15 LE)
 * to validate that the block transfer path works end-to-end.
 *
 * 64-byte block is the BCM43455 SDIO default (CCCR FN0BS / FN1BS).
 * Setting BLOCK_SIZE = 64 matches what brcmfmac uses for control
 * transfers; firmware bulk download eventually uses 512-byte blocks
 * once SDIO clock has been bumped past 400 kHz init speed. */
static int diag_format_sdio_block(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int ready_iters = 0, rdy_iters = 0;
	int rc_cmd53 = -100;
	uint16_t rca = 0;
	uint8_t block[64] = {0};

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-block\n");
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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		/* Program F1 IOBLOCK_SIZE to 64 via FBR1 (CCCR regs 0x110
		 * /0x111). Without this CMD53 block-mode data-phase stalls
		 * because the chip doesn't know what block size to emit. */
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x110u, 0x40u, NULL);  /* LSB = 64 */
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x111u, 0x00u, NULL);  /* MSB */

		/* Window at 0x18000000 (default). Issue CMD53 read of one
		 * 64-byte block at F1 reg 0 -> backplane 0x18000000 (CC). */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x18u, NULL);

		rc_cmd53 = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/1u, /*block_size=*/64u, block);
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=%d/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_iordy;

	r = snprintf(buf + off, cap - off,
		"CMD53 read 1 block * 64B @ F1 reg 0 (CC):  rc=%d\n",
		rc_cmd53);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	if (rc_cmd53 == 0) {
		int w;
		for (w = 0; w < 16; ++w) {
			uint32_t word = block[w * 4] |
				((uint32_t)block[w * 4 + 1] << 8) |
				((uint32_t)block[w * 4 + 2] << 16) |
				((uint32_t)block[w * 4 + 3] << 24);
			r = snprintf(buf + off, cap - off,
				"  +0x%02x  0x%08x\n", w * 4, (unsigned)word);
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
		{
			int chip_id_match = (block[0] == 0x45u && block[1] == 0x43u
				&& block[2] == 0x26u && block[3] == 0x15u);
			r = snprintf(buf + off, cap - off,
				"chip-id match (expect 45 43 26 15): %s\n",
				chip_id_match ? "YES" : "NO");
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
	}

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


/* WiFi P3: CMD53 block-mode WRITE smoke test.
 *
 * Does a CMD53 write of a 64-byte pattern into SOCRAM at chip-internal
 * 0x00198000 (brcmfmac rambase for BCM43455), then CMD53 read-back at
 * the same address, then byte-compare. SOCRAM is writable from host
 * while ARM is held in reset (POR default per Tier-4 results
 * 'A' sub-command — 0x83C ResetCtrl bit 0 = 1 at boot).
 *
 * Successful round-trip validates the bidirectional CMD53 data path,
 * which is the final piece required to actually download
 * brcmfmac43455-sdio.bin into SOCRAM during P3 firmware load. */
static int diag_format_sdio_blockwrite(char *buf, size_t cap)
{
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int ready_iters = 0, rdy_iters = 0;
	int rc_w = -100, rc_r = -100;
	uint16_t rca = 0;
	uint8_t wbuf[64], rbuf[64];
	int i, match_count;

	for (i = 0; i < 64; ++i) {
		wbuf[i] = (uint8_t)(0x40 + i);
		rbuf[i] = 0;
	}

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-blockwrite\n");
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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		/* Set F1 IOBLOCK_SIZE = 64 in FBR1 (CCCR 0x110/0x111). */
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x110u, 0x40u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x111u, 0x00u, NULL);

		/* Window the SBADDR to chip-internal SOCRAM start (0x00198000):
		 *   LOW  bit 7 = bit 15 of addr = (0x198000 >> 15) & 1 = 1 -> 0x80
		 *   MID  byte  = bits[23:16] = 0x19
		 *   HIGH byte  = bits[31:24] = 0x00
		 *   F1 window offset = addr & 0x7FFF = 0x0000 */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x80u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x19u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);

		/* CMD53 write 64 bytes to F1 reg 0 -> chip-internal 0x00198000. */
		rc_w = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/1u, /*block_size=*/64u, wbuf);

		/* CMD53 read back the same 64 bytes. */
		if (rc_w == 0) {
			rc_r = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
				/*reg_addr=*/0u, /*block_count=*/1u, /*block_size=*/64u, rbuf);
		}
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=%d/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_iordy;

	r = snprintf(buf + off, cap - off,
		"CMD53 write rc=%d  CMD53 read rc=%d  SOCRAM @ chip-internal 0x00198000\n",
		rc_w, rc_r);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	if (rc_w == 0 && rc_r == 0) {
		match_count = 0;
		for (i = 0; i < 64; ++i) {
			if (rbuf[i] == wbuf[i]) {
				++match_count;
			}
		}
		r = snprintf(buf + off, cap - off,
			"round-trip: %d/64 bytes match%s\n",
			match_count,
			(match_count == 64) ? " (PASS)" : " (FAIL)");
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		/* Dump first 16 bytes of read-back for sanity. */
		r = snprintf(buf + off, cap - off,
			"  rbuf[0..15] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			rbuf[0], rbuf[1], rbuf[2], rbuf[3],
			rbuf[4], rbuf[5], rbuf[6], rbuf[7],
			rbuf[8], rbuf[9], rbuf[10], rbuf[11],
			rbuf[12], rbuf[13], rbuf[14], rbuf[15]);
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


/* WiFi P3: 4 KB firmware-loader smoke test at SOCRAM rambase.
 *
 * Writes 4 KB of test pattern (byte i = i & 0xff) into chip-internal
 * SOCRAM address 0x00198000 (brcmfmac rambase for BCM43455) via one
 * multi-block CMD53 (block_count=64, block_size=64), then reads it
 * back via the symmetric CMD53 and byte-compares.
 *
 * Extends the 'W' (sdio-blockwrite) coverage in two ways:
 *   - 4 KB transfer in one CMD53 instead of 64 bytes — exercises the
 *     BUF_WR_READY / BUF_RD_READY PIO drain across many blocks
 *   - validates SOCRAM is writable for at least a full window-fraction
 *     before we commit to walking the entire 32 KB SBADDR window
 *
 * Note on chip-internal 0x0: an earlier revision of this command
 * targeted 0x0 and found it is BootROM (read-only for bytes 32+).
 * ARM-CR4 fetches from 0x0 after reset release, but the BootROM
 * there trampolines to 0x198000 where the downloaded firmware lives,
 * per the standard brcmfmac convention.
 *
 * Successful 4 KB round-trip is the last prerequisite before walking
 * SBADDR through the 643 KB brcmfmac43455-sdio.bin blob. */
static int diag_format_sdio_fwloadtest(char *buf, size_t cap)
{
	static uint8_t wbuf[4096];
	static uint8_t rbuf[4096];
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int ready_iters = 0, rdy_iters = 0;
	int rc_w = -100, rc_r = -100;
	uint16_t rca = 0;
	int i, match_count;
	int first_mismatch[4] = {-1, -1, -1, -1};
	int mismatch_filled = 0;

	for (i = 0; i < (int)sizeof(wbuf); ++i) {
		wbuf[i] = (uint8_t)(i & 0xff);
		rbuf[i] = 0;
	}

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-fwloadtest\n");
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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		(void)diag_sdioCmd52(sdhci, 1, 0, 0x110u, 0x40u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x111u, 0x00u, NULL);

		/* Window SBADDR to chip-internal 0x00198000 (SOCRAM rambase
		 * for BCM43455 per brcmfmac):
		 *   LOW  bit 7 = bit 15 of addr = (0x198000 >> 15) & 1 = 1 -> 0x80
		 *   MID  byte  = bits[23:16] = 0x19
		 *   HIGH byte  = bits[31:24] = 0x00
		 *   F1 window offset = addr & 0x7FFF = 0 */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x80u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x19u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);

		rc_w = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/64u, /*block_size=*/64u, wbuf);

		if (rc_w == 0) {
			rc_r = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
				/*reg_addr=*/0u, /*block_count=*/64u, /*block_size=*/64u, rbuf);
		}
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=%d/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_iordy;

	r = snprintf(buf + off, cap - off,
		"CMD53 write rc=%d  CMD53 read rc=%d  target chip-internal 0x00198000 (4 KB)\n",
		rc_w, rc_r);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	if (rc_w == 0 && rc_r == 0) {
		match_count = 0;
		for (i = 0; i < (int)sizeof(wbuf); ++i) {
			if (rbuf[i] == wbuf[i]) {
				++match_count;
			}
			else if (mismatch_filled < 4) {
				first_mismatch[mismatch_filled++] = i;
			}
		}
		r = snprintf(buf + off, cap - off,
			"round-trip: %d/%d bytes match%s\n",
			match_count, (int)sizeof(wbuf),
			(match_count == (int)sizeof(wbuf)) ? " (PASS)" : " (FAIL)");
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		r = snprintf(buf + off, cap - off,
			"  rbuf[0..15] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			rbuf[0], rbuf[1], rbuf[2], rbuf[3],
			rbuf[4], rbuf[5], rbuf[6], rbuf[7],
			rbuf[8], rbuf[9], rbuf[10], rbuf[11],
			rbuf[12], rbuf[13], rbuf[14], rbuf[15]);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		if (mismatch_filled > 0) {
			r = snprintf(buf + off, cap - off,
				"  first mismatches @ idx %d %d %d %d  (rbuf=%02x %02x %02x %02x  wbuf=%02x %02x %02x %02x)\n",
				first_mismatch[0], first_mismatch[1],
				first_mismatch[2], first_mismatch[3],
				first_mismatch[0] >= 0 ? rbuf[first_mismatch[0]] : 0,
				first_mismatch[1] >= 0 ? rbuf[first_mismatch[1]] : 0,
				first_mismatch[2] >= 0 ? rbuf[first_mismatch[2]] : 0,
				first_mismatch[3] >= 0 ? rbuf[first_mismatch[3]] : 0,
				first_mismatch[0] >= 0 ? wbuf[first_mismatch[0]] : 0,
				first_mismatch[1] >= 0 ? wbuf[first_mismatch[1]] : 0,
				first_mismatch[2] >= 0 ? wbuf[first_mismatch[2]] : 0,
				first_mismatch[3] >= 0 ? wbuf[first_mismatch[3]] : 0);
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
	}

	r = snprintf(buf + off, cap - off, ".\n");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	return off;
}


/* WiFi P3: SBADDR multi-window walk smoke test.
 *
 * Writes two distinct 4 KB patterns to two adjacent SBADDR windows
 * (chip-internal 0x00198000 and 0x001A0000 — 32 KB apart, the F1
 * window granularity), then reads each back independently and
 * byte-compares.
 *
 * Patterns are deliberately different per window:
 *   window 0 @ 0x198000:  byte i =  i        (0x00..0xff, repeating)
 *   window 1 @ 0x1A0000:  byte i = ~i        (0xff..0x00, repeating)
 *
 * Three things validated by a clean run:
 *   1. SBADDR LOW/MID/HIGH walk works — writing window 1 doesn't
 *      clobber window 0, reading window 0 doesn't return window 1.
 *   2. The 32 KB window boundary is at the address we think it is.
 *   3. The host PIO drain handles back-to-back CMD53 reissues on the
 *      same F1 with no inter-command reset.
 *
 * This is the last verification step before staging the actual
 * 643 KB brcmfmac43455-sdio.bin blob and walking it across ~21
 * SBADDR windows for the real firmware download. */
static int diag_format_sdio_fwwalk(char *buf, size_t cap)
{
	static uint8_t wbuf0[4096];
	static uint8_t wbuf1[4096];
	static uint8_t rbuf0[4096];
	static uint8_t rbuf1[4096];
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int ready_iters = 0, rdy_iters = 0;
	int rc_w0 = -100, rc_w1 = -100, rc_r0 = -100, rc_r1 = -100;
	uint16_t rca = 0;
	int i, m0, m1, m_cross;

	for (i = 0; i < (int)sizeof(wbuf0); ++i) {
		wbuf0[i] = (uint8_t)(i & 0xff);
		wbuf1[i] = (uint8_t)(~i & 0xff);
		rbuf0[i] = 0;
		rbuf1[i] = 0;
	}

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-fwwalk\n");
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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		(void)diag_sdioCmd52(sdhci, 1, 0, 0x110u, 0x40u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x111u, 0x00u, NULL);

		/* Window 0: chip-internal 0x00198000
		 *   LOW bit 7 = bit 15 of addr = 1 -> 0x80
		 *   MID = bits[23:16] = 0x19
		 *   HIGH = bits[31:24] = 0x00 */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x80u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x19u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);

		rc_w0 = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/64u, /*block_size=*/64u, wbuf0);

		/* Window 1: chip-internal 0x001A0000
		 *   LOW bit 7 = bit 15 of addr = 0 -> 0x00
		 *   MID = bits[23:16] = 0x1A
		 *   HIGH = bits[31:24] = 0x00 */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x1Au, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);

		rc_w1 = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/64u, /*block_size=*/64u, wbuf1);

		/* Read back window 1 first (current SBADDR position). */
		rc_r1 = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/64u, /*block_size=*/64u, rbuf1);

		/* Re-window to 0x198000 and read back window 0. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x80u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x19u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);

		rc_r0 = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/64u, /*block_size=*/64u, rbuf0);
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=%d/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_iordy;

	r = snprintf(buf + off, cap - off,
		"win0 @0x198000  write rc=%d  read rc=%d\n",
		rc_w0, rc_r0);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	r = snprintf(buf + off, cap - off,
		"win1 @0x1A0000  write rc=%d  read rc=%d\n",
		rc_w1, rc_r1);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	if (rc_w0 == 0 && rc_w1 == 0 && rc_r0 == 0 && rc_r1 == 0) {
		m0 = 0;
		m1 = 0;
		m_cross = 0;
		for (i = 0; i < (int)sizeof(wbuf0); ++i) {
			if (rbuf0[i] == wbuf0[i]) {
				++m0;
			}
			if (rbuf1[i] == wbuf1[i]) {
				++m1;
			}
			/* Cross-window bleed indicator: did either readback
			 * happen to return the OTHER window's pattern? */
			if (rbuf0[i] == wbuf1[i]) {
				++m_cross;
			}
		}
		r = snprintf(buf + off, cap - off,
			"win0 match %d/%d  win1 match %d/%d  cross-bleed %d/%d  %s\n",
			m0, (int)sizeof(wbuf0),
			m1, (int)sizeof(wbuf1),
			m_cross, (int)sizeof(wbuf0),
			(m0 == (int)sizeof(wbuf0) && m1 == (int)sizeof(wbuf1)) ?
				"(PASS)" : "(FAIL)");
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		r = snprintf(buf + off, cap - off,
			"  win0[0..7] %02x %02x %02x %02x %02x %02x %02x %02x  "
			"win1[0..7] %02x %02x %02x %02x %02x %02x %02x %02x\n",
			rbuf0[0], rbuf0[1], rbuf0[2], rbuf0[3],
			rbuf0[4], rbuf0[5], rbuf0[6], rbuf0[7],
			rbuf1[0], rbuf1[1], rbuf1[2], rbuf1[3],
			rbuf1[4], rbuf1[5], rbuf1[6], rbuf1[7]);
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


/* WiFi P3: full-firmware load into SOCRAM.
 *
 * Walks the full 643 KB staged Cypress brcmfmac43455-sdio.bin
 * (embedded as wifi_fw_43455[]) into chip-internal SOCRAM starting
 * at rambase 0x00198000, across ~20 SBADDR windows of 32 KB each.
 * Each window's full payload goes in ONE CMD53 multi-block transfer
 * (block_count=64, block_size=512 → 32 KB per CMD53) at SDIO HS-mode
 * (25 MHz / 4-bit) so the entire load fits comfortably under one
 * UDP-response budget — ~50 ms at 12.5 MB/s.
 *
 * Slicing:
 *   - 19 windows × 32 KB = 622592 bytes
 *   - 1 final window of 41 × 512 = 20992 bytes
 *   - Total 643584 bytes (67 bytes short of 643651 — see TODO below)
 *
 * After the load, re-windows back to 0x198000 and reads the first
 * 4 KB to verify the head of firmware survived intact.
 *
 * TODO: handle the final 67 bytes via byte-mode CMD53 (block_mode=0).
 * Currently the last 67 bytes of the firmware blob aren't written.
 * For smoke testing this is fine; for actual chip boot we'll add a
 * byte-mode helper next iteration. */
static int diag_format_sdio_fwload(char *buf, size_t cap)
{
	static uint8_t verify_buf[4096];
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int rc_hs = -100;
	int ready_iters = 0, rdy_iters = 0;
	uint16_t rca = 0;
	int rc_w, rc_r = -100;
	int worst_rc_w = 0;
	int match_count = 0;
	int i;
	uint32_t bytes_written = 0u;
	int window_idx = 0;
	size_t fw_offset = 0u;
	size_t fw_target_bytes;
	const uint32_t window_bytes = 32u * 1024u;
	const uint32_t blk_size = 64u;     /* keep same as 'H' / 'L' until 512 works */
	const uint32_t blk_count = 64u;    /* per CMD53 -> 4 KB; 8 CMD53s per window */

	for (i = 0; i < (int)sizeof(verify_buf); ++i) {
		verify_buf[i] = 0;
	}

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-fwload\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	if (wifi_fw_43455_len == 0u) {
		r = snprintf(buf + off, cap - off,
			"error: firmware blob not staged (wifi_fw_43455_len=0)\n"
			"hint: scripts/stage-bcm43455-firmware.sh then rebuild\n.\n");
		return off + (r > 0 ? r : 0);
	}

	/* Round target down to a 512-byte block boundary. */
	fw_target_bytes = (wifi_fw_43455_len / blk_size) * blk_size;

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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		/* Bump SDIO to HS-mode (25 MHz / 4-bit). Bus jumps from
		 * 50 KB/s to 12.5 MB/s so the full 643 KB fits in ~50 ms. */
		rc_hs = diag_sdioGoHighSpeed(sdhci);

		/* F1 IOBLOCK_SIZE = 64 (matches blk_size used in CMD53s). */
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x110u, 0x40u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x111u, 0x00u, NULL);

		/* Walk firmware across SBADDR windows. Each window holds
		 * 32 KB; the last window is partial. Within each window, 8
		 * CMD53s of 4 KB each (block_count=64, block_size=64). */
		while (fw_offset < fw_target_bytes && rc_hs == 0) {
			uint32_t addr = 0x00198000u + (uint32_t)window_idx * 0x8000u;
			uint8_t  lo  = (uint8_t)(((addr >> 15) & 1u) ? 0x80u : 0x00u);
			uint8_t  mid = (uint8_t)((addr >> 16) & 0xffu);
			uint8_t  hi  = (uint8_t)((addr >> 24) & 0xffu);
			size_t   remaining = fw_target_bytes - fw_offset;
			size_t   this_window = (remaining > window_bytes) ? window_bytes : remaining;
			uint32_t bytes_per_cmd = blk_count * blk_size;  /* 4096 */
			uint32_t chunks = (uint32_t)(this_window / bytes_per_cmd);
			uint32_t leftover_blocks = (uint32_t)((this_window % bytes_per_cmd) / blk_size);
			uint32_t ci;

			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, lo,  NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, mid, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, hi,  NULL);

			for (ci = 0; ci < chunks; ++ci) {
				rc_w = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
					/*reg_addr=*/ci * bytes_per_cmd,
					/*block_count=*/blk_count,
					/*block_size=*/blk_size,
					wifi_fw_43455 + fw_offset + ci * bytes_per_cmd);
				if (rc_w != 0) {
					if (worst_rc_w == 0) {
						worst_rc_w = rc_w;
					}
					break;
				}
				bytes_written += bytes_per_cmd;
			}
			if (rc_w != 0) {
				break;
			}

			if (leftover_blocks > 0) {
				rc_w = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
					/*reg_addr=*/chunks * bytes_per_cmd,
					/*block_count=*/leftover_blocks,
					/*block_size=*/blk_size,
					wifi_fw_43455 + fw_offset + chunks * bytes_per_cmd);
				if (rc_w != 0) {
					if (worst_rc_w == 0) {
						worst_rc_w = rc_w;
					}
					break;
				}
				bytes_written += leftover_blocks * blk_size;
			}

			fw_offset += this_window;
			window_idx++;
		}

		/* Re-window to firmware start and verify first 4 KB. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x80u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x19u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);

		rc_r = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/64u, /*block_size=*/64u,
			verify_buf);
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=%d/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_iordy;

	r = snprintf(buf + off, cap - off,
		"fw_len=%zu  target=%zu  staged %u bytes across %d windows  "
		"HS=%d  worst rc_w=%d  rc_r=%d\n",
		wifi_fw_43455_len, fw_target_bytes, bytes_written, window_idx,
		rc_hs, worst_rc_w, rc_r);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	if (rc_r == 0 && worst_rc_w == 0) {
		match_count = 0;
		for (i = 0; i < (int)sizeof(verify_buf); ++i) {
			if (verify_buf[i] == wifi_fw_43455[i]) {
				++match_count;
			}
		}
		r = snprintf(buf + off, cap - off,
			"verify first 4KB: %d/%d match  %s\n",
			match_count, (int)sizeof(verify_buf),
			(match_count == (int)sizeof(verify_buf)) ? "(PASS)" : "(FAIL)");
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		r = snprintf(buf + off, cap - off,
			"  fw[0..7] %02x %02x %02x %02x %02x %02x %02x %02x  "
			"rb[0..7] %02x %02x %02x %02x %02x %02x %02x %02x\n",
			wifi_fw_43455[0], wifi_fw_43455[1], wifi_fw_43455[2], wifi_fw_43455[3],
			wifi_fw_43455[4], wifi_fw_43455[5], wifi_fw_43455[6], wifi_fw_43455[7],
			verify_buf[0], verify_buf[1], verify_buf[2], verify_buf[3],
			verify_buf[4], verify_buf[5], verify_buf[6], verify_buf[7]);
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


/* WiFi P3: SDIO HS-mode (25 MHz / 4-bit) bus-speed smoke test.
 *
 * Standard enum → F1 enable → diag_sdioGoHighSpeed() → 4 KB CMD53
 * round-trip at chip-internal 0x198000 — same target/payload as
 * 'L', but at 12.5 MB/s instead of 50 KB/s. PASS = same 4096/4096
 * round-trip score AND HS-mode switch returned rc=0.
 *
 * If this passes, the actual firmware loader can downshift to a
 * single CMD53-per-window walk over the full 643 KB blob and still
 * fit comfortably inside a UDP-response timeout. */
static int diag_format_sdio_hs(char *buf, size_t cap)
{
	static uint8_t wbuf[4096];
	static uint8_t rbuf[4096];
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	uint32_t hs_check_resp[4] = {0}, bic_check_resp[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int ready_iters = 0, rdy_iters = 0;
	int rc_w = -100, rc_r = -100, rc_hs = -100;
	uint16_t rca = 0;
	int i, match_count;

	for (i = 0; i < (int)sizeof(wbuf); ++i) {
		wbuf[i] = (uint8_t)(i & 0xff);
		rbuf[i] = 0;
	}

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-hs\n");
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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		rc_hs = diag_sdioGoHighSpeed(sdhci);

		/* Read back CCCR 0x13 and 0x07 to confirm what stuck. */
		(void)diag_sdioCmd52(sdhci, 0, 0, 0x13u, 0u, hs_check_resp);
		(void)diag_sdioCmd52(sdhci, 0, 0, 0x07u, 0u, bic_check_resp);

		(void)diag_sdioCmd52(sdhci, 1, 0, 0x110u, 0x40u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x111u, 0x00u, NULL);

		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x80u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x19u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);

		rc_w = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/64u, /*block_size=*/64u, wbuf);
		if (rc_w == 0) {
			rc_r = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
				/*reg_addr=*/0u, /*block_count=*/64u, /*block_size=*/64u, rbuf);
		}
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=%d/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_iordy;

	r = snprintf(buf + off, cap - off,
		"HS switch rc=%d  CCCR[0x13]=0x%02x (SHS|EHS|bit-spd)  CCCR[0x07]=0x%02x (BIC)\n",
		rc_hs,
		(unsigned)(hs_check_resp[0] & 0xff),
		(unsigned)(bic_check_resp[0] & 0xff));
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"CMD53 write rc=%d  CMD53 read rc=%d  target 0x00198000 (4 KB @ HS-mode)\n",
		rc_w, rc_r);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	if (rc_w == 0 && rc_r == 0) {
		match_count = 0;
		for (i = 0; i < (int)sizeof(wbuf); ++i) {
			if (rbuf[i] == wbuf[i]) {
				++match_count;
			}
		}
		r = snprintf(buf + off, cap - off,
			"round-trip: %d/%d bytes match%s\n",
			match_count, (int)sizeof(wbuf),
			(match_count == (int)sizeof(wbuf)) ? " (PASS)" : " (FAIL)");
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		r = snprintf(buf + off, cap - off,
			"  rbuf[0..15] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			rbuf[0], rbuf[1], rbuf[2], rbuf[3],
			rbuf[4], rbuf[5], rbuf[6], rbuf[7],
			rbuf[8], rbuf[9], rbuf[10], rbuf[11],
			rbuf[12], rbuf[13], rbuf[14], rbuf[15]);
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


/* WiFi P3 final: full-firmware load + release ARM-CR4 + look for fw boot.
 *
 * Same load pipeline as 'I' (enum → F1 enable → HS-mode → walk 643 KB
 * into SOCRAM), then:
 *
 *   1. Re-window SBADDR to chip-internal 0x18100000 (ARM-CR4 wrapper
 *      window 0x18103000 lives here at F1 offset 0x3000).
 *   2. Read ResetCtrl at F1 offset 0x3800 — expect 0x01 (POR: held).
 *   3. Write 0x00 to ResetCtrl — release ARM-CR4. The core fetches
 *      its first instruction from BootROM at chip-internal 0x0,
 *      which trampolines to SOCRAM @ 0x198000 where we just dropped
 *      the Cypress firmware.
 *   4. Sleep ~100 ms to let firmware initialize.
 *   5. Re-window SBADDR to chip-internal 0x198000 and CMD53-read
 *      the first 64 bytes of SOCRAM.
 *   6. Compare against the source blob's first 64 bytes: if firmware
 *      has booted and written anything to its own image, the bytes
 *      will differ — that's the "fw running" signal (the SOCRAM
 *      head usually holds the firmware's startup data area).
 *
 * No NVRAM is loaded yet, so the chip won't fully come up; we expect
 * SOME firmware activity (changed bytes in SOCRAM head, or
 * SBINTSTATUS bits set) but not a full BCDC hello. This is the
 * pre-flight check that the load pipeline + ARM release work. */
static int diag_format_sdio_fwrelease(char *buf, size_t cap)
{
	static uint8_t pre_buf[64];
	static uint8_t post_buf[64];
	int off = 0, r;
	void *gpio_page, *sdhci_page;
	uint32_t ocr_resp[4] = {0}, claim_resp[4] = {0};
	uint32_t rca_resp[4] = {0}, sel_resp[4] = {0};
	uint32_t ioen_pre_resp[4] = {0}, iordy_resp[4] = {0};
	uint32_t rc_pre_resp[4] = {0}, rc_post_resp[4] = {0};
	int rc_ocr = -1, rc_claim = -1, rc_sel = -1, rc_iordy = -1;
	int rc_hs = -100;
	int ready_iters = 0, rdy_iters = 0;
	uint16_t rca = 0;
	int rc_w, rc_r_pre = -100, rc_r_post = -100;
	int rc_nvram_w = -100;
	int rc_tail = -100;
	uint8_t chipclk_samples[8] = {0};
	uint8_t socram_tail[16] = {0};
	uint8_t scan_buf[64];
	int scan_rc[6] = {0};
	int scan_diff[6] = {0};
	int scan_changed_pts = -1;
	uint8_t ht_clk_csr = 0u;
	uint8_t f2_ready = 0u;
	int f2_ready_iters = -1;
	uint8_t rstvec_rb[4] = {0};
	uint32_t hmb_data = 0u;
	unsigned card_intr = 0u;
	int worst_rc_w = 0;
	int i, pre_match, post_match, diff_count;
	uint32_t bytes_written = 0u;
	int window_idx = 0;
	size_t fw_offset = 0u;
	size_t fw_target_bytes;
	const uint32_t window_bytes = 32u * 1024u;
	const uint32_t blk_size = 64u;
	const uint32_t blk_count = 64u;

	for (i = 0; i < (int)sizeof(pre_buf); ++i) {
		pre_buf[i] = 0;
		post_buf[i] = 0;
	}

	r = snprintf(buf + off, cap - off, "PHX-DIAG/1 sdio-fwrelease\n");
	if (r < 0 || (size_t)r >= cap - off) {
		return -1;
	}
	off += r;

	if (wifi_fw_43455_len == 0u) {
		r = snprintf(buf + off, cap - off,
			"error: firmware blob not staged\n.\n");
		return off + (r > 0 ? r : 0);
	}
	fw_target_bytes = (wifi_fw_43455_len / blk_size) * blk_size;

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

		for (i = 34; i <= 39; ++i) {
			diag_gpioSetFsel(gpio, (unsigned)i, 7u);
		}
		diag_wifiPowerCycle();
		(void)diag_sdhciSetClockKHz(sdhci, 400u);
		(void)diag_sdhciResetCmdDat(sdhci);

		(void)diag_sdhciCmd(sdhci, 0u, 0u, SDHCI_RESP_R0, NULL);
		usleep(1000);
		rc_ocr = diag_sdhciCmd(sdhci, 5u, 0u, SDHCI_RESP_R4, ocr_resp);
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
		(void)diag_sdhciCmd(sdhci, 3u, 0u, SDHCI_RESP_R6, rca_resp);
		rca = (uint16_t)((rca_resp[0] >> 16) & 0xFFFFu);
		rc_sel = diag_sdhciCmd(sdhci, 7u, (uint32_t)rca << 16, SDHCI_RESP_R1, sel_resp);

		(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_pre_resp);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
			(uint8_t)((ioen_pre_resp[0] | 0x02u) & 0xffu), NULL);
		for (rdy_iters = 0; rdy_iters < 50; ++rdy_iters) {
			rc_iordy = diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, iordy_resp);
			if (rc_iordy != 0) {
				break;
			}
			if ((iordy_resp[0] & 0x02u) != 0u) {
				rdy_iters++;
				break;
			}
			usleep(1000);
		}

		/* KSO (Keep-SDIO-On) enable. SDIO core rev >= 12 (43455 qualifies)
		 * gates the backplane clock on KSO; without it the device can
		 * drop the clock and HT_AVAIL never latches. SLEEPCSR (F1
		 * 0x1001F) bit 0 = KSO_EN. RMW. (bwfm bwfm_sdio_attach /
		 * brcmfmac brcmf_sdio_kso_init.) */
		{
			uint32_t kso[4] = {0};
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x1001Fu, 0u, kso);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1001Fu,
				(uint8_t)((kso[0] | 0x01u) & 0xffu), NULL);
		}

		rc_hs = diag_sdioGoHighSpeed(sdhci);

		/* Backplane clock bring-up before CR4 release: ALP ONLY.
		 * Per brcmfmac brcmf_sdio_load_firmware(), the host sets
		 * alp_only=true for the whole firmware-download + CR4-release
		 * window and brings the backplane up on ALP only
		 * (SBSDIO_ALP_AVAIL_REQ 0x08; wait SBSDIO_ALP_AVAIL 0x40). It
		 * does NOT request/await HT and does NO PMU resource-mask or
		 * RES_RELOAD programming on the SDIO path — the firmware running
		 * on the CR4 brings HT up itself once executing; the host only
		 * force-enables HT (FORCE_HT) AFTER firmware is up, for F2 IRQ
		 * propagation. Forcing HT here cannot work: the CR4 is a
		 * high-speed core with no HT clock until firmware requests it, so
		 * the old host-side HT_AVAIL_REQ/FORCE_HT + PMUCONTROL RES_RELOAD
		 * just spun (CHIPCLKCSR stuck 0x50/0x00) — the identical signature
		 * seen in OpenWrt #23069 / starfive #51, whose root cause is
		 * "firmware not executing", not a missing PMU write. (Refs:
		 * torvalds/linux brcmfmac sdio.c alp_only L4234 + htclk L784;
		 * chip.c brcmf_chip_cr4_set_active L1339.) HT_AVAIL is polled
		 * AFTER release below as the firmware-alive tell. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Eu, 0x08u, NULL);
		for (i = 0; i < 250; ++i) {
			uint32_t cc[4] = {0};
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x1000Eu, 0u, cc);
			ht_clk_csr = (uint8_t)(cc[0] & 0xffu);
			if ((ht_clk_csr & 0x40u) != 0u) {
				break;
			}
			usleep(2000);
		}

		(void)diag_sdioCmd52(sdhci, 1, 0, 0x110u, 0x40u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 0, 0x111u, 0x00u, NULL);

		while (fw_offset < fw_target_bytes && rc_hs == 0) {
			uint32_t addr = 0x00198000u + (uint32_t)window_idx * 0x8000u;
			uint8_t  lo  = (uint8_t)(((addr >> 15) & 1u) ? 0x80u : 0x00u);
			uint8_t  mid = (uint8_t)((addr >> 16) & 0xffu);
			uint8_t  hi  = (uint8_t)((addr >> 24) & 0xffu);
			size_t   remaining = fw_target_bytes - fw_offset;
			size_t   this_window = (remaining > window_bytes) ? window_bytes : remaining;
			uint32_t bytes_per_cmd = blk_count * blk_size;
			uint32_t chunks = (uint32_t)(this_window / bytes_per_cmd);
			uint32_t leftover_blocks = (uint32_t)((this_window % bytes_per_cmd) / blk_size);
			uint32_t ci;

			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, lo,  NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, mid, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, hi,  NULL);

			for (ci = 0; ci < chunks; ++ci) {
				rc_w = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
					/*reg_addr=*/ci * bytes_per_cmd,
					/*block_count=*/blk_count,
					/*block_size=*/blk_size,
					wifi_fw_43455 + fw_offset + ci * bytes_per_cmd);
				if (rc_w != 0) {
					if (worst_rc_w == 0) worst_rc_w = rc_w;
					break;
				}
				bytes_written += bytes_per_cmd;
			}
			if (rc_w != 0) break;

			if (leftover_blocks > 0) {
				rc_w = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
					/*reg_addr=*/chunks * bytes_per_cmd,
					/*block_count=*/leftover_blocks,
					/*block_size=*/blk_size,
					wifi_fw_43455 + fw_offset + chunks * bytes_per_cmd);
				if (rc_w != 0) {
					if (worst_rc_w == 0) worst_rc_w = rc_w;
					break;
				}
				bytes_written += leftover_blocks * blk_size;
			}

			fw_offset += this_window;
			window_idx++;
		}

		/* NVRAM load: chip-ready blob (stripped + length-magic
		 * trailer) goes at chip-internal (rambase + ramsize -
		 * wifi_nvram_43455_len) = 0x238000 - 1728 = 0x237940,
		 * inside SBADDR window 19. The python preprocessor pads
		 * the blob to a 64-byte boundary, so it lands as a single
		 * CMD53 multi-block write. */
		{
			uint32_t nv_start = 0x238000u - (uint32_t)wifi_nvram_43455_len;
			uint8_t  nv_lo  = (uint8_t)(((nv_start >> 15) & 1u) ? 0x80u : 0x00u);
			uint8_t  nv_mid = (uint8_t)((nv_start >> 16) & 0xffu);
			uint8_t  nv_hi  = (uint8_t)((nv_start >> 24) & 0xffu);
			uint32_t nv_f1_offset = nv_start & 0x7FFFu;
			uint32_t nv_blocks = (uint32_t)(wifi_nvram_43455_len / 64u);

			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, nv_lo,  NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, nv_mid, NULL);
			(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, nv_hi,  NULL);

			rc_nvram_w = diag_sdioCmd53Write(sdhci, 1, /*incr=*/1,
				/*reg_addr=*/nv_f1_offset,
				/*block_count=*/nv_blocks,
				/*block_size=*/64u, wifi_nvram_43455);
		}

		/* Snapshot SOCRAM[0..63] BEFORE release — should match
		 * source firmware byte-identically. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x80u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x19u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);
		rc_r_pre = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/1u, /*block_size=*/64u, pre_buf);

		/* brcmfmac CR4 activation, step 1: write the firmware reset
		 * vector (first word of the blob) to chip-internal address 0.
		 * The SDIO `activate` callback does exactly this via ramrw.
		 * The low 32 bytes of address 0 are a writable vector-table
		 * overlay (confirmed by the 'L' probe); the CR4 fetches its
		 * reset vector from here when it leaves reset. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x0u, wifi_fw_43455[0], NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1u, wifi_fw_43455[1], NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x2u, wifi_fw_43455[2], NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x3u, wifi_fw_43455[3], NULL);

		/* Read addr 0 back to VERIFY the rstvec landed at TRUE backplane
		 * address 0 (WHD does this exact assert in download_resource). If
		 * it does not read back == fw[0..3], the addr-0 write is landing in
		 * TCM/0x198000 (SBADDR window / address-mask bug) and the CR4
		 * fetches a garbage reset vector — which fully explains "CR4
		 * clocked+unhalted (IoCtrl=0x01) but firmware not executing". */
		{
			uint32_t v0[4] = {0}, v1[4] = {0}, v2[4] = {0}, v3[4] = {0};
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x0u, 0u, v0);
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x1u, 0u, v1);
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x2u, 0u, v2);
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x3u, 0u, v3);
			rstvec_rb[0] = (uint8_t)(v0[0] & 0xffu);
			rstvec_rb[1] = (uint8_t)(v1[0] & 0xffu);
			rstvec_rb[2] = (uint8_t)(v2[0] & 0xffu);
			rstvec_rb[3] = (uint8_t)(v3[0] & 0xffu);
		}

		/* Re-window to ARM-CR4 wrapper window 0x18100000:
		 *   F1 0x2408 = chip-internal 0x18102408 = BCMA_IOCTL
		 *   F1 0x2800 = chip-internal 0x18102800 = BCMA_RESET_CTL */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x10u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x18u, NULL);

		/* Read IOCTL pre (POR observed 0x21 = CPUHALT|CLK). */
		(void)diag_sdioCmd52(sdhci, 0, 1, 0x2408u, 0u, rc_pre_resp);

		/* brcmfmac CR4 activation, step 2: full AXI resetcore toggle,
		 * resetcore(core, prereset=CPUHALT(0x20), reset=0, postreset=0):
		 *
		 *   coredisable(prereset=0x20, reset=0):
		 *     IOCTL      = prereset | FGC(0x02) | CLK(0x01) = 0x23
		 *     RESET_CTL  = RESET(0x01)
		 *     IOCTL      = reset(0) | FGC | CLK            = 0x03
		 *   deassert:
		 *     RESET_CTL  = 0  (then poll until clear)
		 *   finalize:
		 *     IOCTL      = postreset(0) | CLK              = 0x01
		 *
		 * Bit values are byte-0-only (CPUHALT=0x20, FGC=0x02, CLK=0x01,
		 * RESET=0x01), so single-byte CMD52 to F1 0x2408 / 0x2800
		 * suffices; the upper 3 bytes of these AXI regs stay zero. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x2408u, 0x23u, NULL);   /* IOCTL CPUHALT|FGC|CLK */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x2800u, 0x01u, NULL);   /* RESET_CTL assert */
		(void)diag_sdioCmd52(sdhci, 0, 1, 0x2800u, 0u, NULL);      /* readback settle */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x2408u, 0x03u, NULL);   /* IOCTL FGC|CLK (reset=0) */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x2800u, 0x00u, NULL);   /* RESET_CTL deassert */
		for (i = 0; i < 50; ++i) {
			uint32_t rcv[4] = {0};
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x2800u, 0u, rcv);
			if ((rcv[0] & 0x01u) == 0u) {
				break;
			}
			usleep(1000);
		}
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x2408u, 0x01u, NULL);   /* IOCTL CLK (CPU runs) */

		/* Post-release SDIO handshake (brcmfmac brcmf_sdio_bus_init):
		 * once the CR4 is running, enable function 2 (the SDPCM data
		 * channel) via CCCR IOEN bit 2 (0x04) and wait for F2-ready in
		 * CCCR IOR bit 2 (0x04). The 43455 firmware brings up its HT/PLL
		 * + data path as it comes ready; some firmware does not proceed
		 * (nor raise HT) until the host enables F2. ~1 s poll budget. */
		{
			uint32_t ioen_resp[4] = {0};
			(void)diag_sdioCmd52(sdhci, 0, 0, 0x02u, 0u, ioen_resp);
			(void)diag_sdioCmd52(sdhci, 1, 0, 0x02u,
				(uint8_t)((ioen_resp[0] | 0x04u) & 0xffu), NULL);  /* IOEN F2 */
			for (i = 0; i < 500; ++i) {
				uint32_t ior_resp[4] = {0};
				(void)diag_sdioCmd52(sdhci, 0, 0, 0x03u, 0u, ior_resp);
				f2_ready = (uint8_t)(ior_resp[0] & 0xffu);
				if ((f2_ready & 0x04u) != 0u) {
					f2_ready_iters = i;
					break;
				}
				usleep(2000);
			}
		}

		usleep(300 * 1000);  /* firmware init: NVRAM parse + chip-self-test */

		/* Read IOCTL post (expect 0x01 = CLK only, CPU running). */
		(void)diag_sdioCmd52(sdhci, 0, 1, 0x2408u, 0u, rc_post_resp);

		/* Re-window to SOCRAM and capture post-release snapshot. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x80u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x19u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);
		rc_r_post = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0u, /*block_count=*/1u, /*block_size=*/64u, post_buf);

		/* fw-execution disambiguation (#91): SOCRAM[0..63] is entry/vector
		 * code a running fw need not modify, so it is a weak "alive" tell.
		 * Scan several points spread across the loaded image and compare
		 * the post-release on-chip bytes to the source blob. ANY changed
		 * point => the CR4 IS executing (writing its data/BSS) and the
		 * problem is observability/early-stall; zero change everywhere =>
		 * fw genuinely not running (chase rstvec/activate). Reads use
		 * 64-byte blocks (F1 block size is 64; non-64 reads return -EIO). */
		{
			static const uint32_t scan_off[6] = {
				0x02000u, 0x10000u, 0x30000u, 0x60000u, 0x90000u, 0x9C000u
			};
			unsigned s;
			int k;
			scan_changed_pts = 0;
			for (s = 0u; s < 6u; ++s) {
				uint32_t a = 0x198000u + scan_off[s];
				uint8_t lo = (uint8_t)(((a >> 15) & 1u) ? 0x80u : 0x00u);
				uint8_t mid = (uint8_t)((a >> 16) & 0xffu);
				uint8_t hi = (uint8_t)((a >> 24) & 0xffu);
				uint32_t f1 = a & 0x7FFFu;
				int d = 0;
				(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, lo, NULL);
				(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, mid, NULL);
				(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, hi, NULL);
				scan_rc[s] = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
					/*reg_addr=*/f1, /*block_count=*/1u, /*block_size=*/64u,
					scan_buf);
				if (scan_rc[s] == 0) {
					for (k = 0; k < 64; ++k) {
						if (scan_buf[k] != wifi_fw_43455[scan_off[s] + (uint32_t)k]) {
							++d;
						}
					}
					scan_diff[s] = d;
					if (d > 0) {
						++scan_changed_pts;
					}
				}
				else {
					scan_diff[s] = -1;
				}
			}
		}

		/* Firmware-running probes:
		 *
		 * 1. CHIPCLKCSR (F1 reg 0x1000E): HT_AVAIL (bit 7, 0x80) goes
		 *    high once the booted firmware requests the high-throughput
		 *    backplane clock. Poll it across ~240 ms to catch the
		 *    transition.
		 * 2. SDHCI INT_STATUS CARD_INTR (bit 8): the chip asserts its
		 *    SDIO interrupt line when firmware has a mailbox message
		 *    (the BCDC "fw ready" hello).
		 * 3. SOCRAM trailer at chip-internal 0x237FFC (the NVRAM
		 *    length-magic word we wrote): firmware overwrites this
		 *    region after parsing NVRAM, so a changed value here is
		 *    another "fw alive" tell. */
		for (i = 0; i < 8; ++i) {
			uint32_t ccsr[4] = {0};
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x1000Eu, 0u, ccsr);
			chipclk_samples[i] = (uint8_t)(ccsr[0] & 0xffu);
			usleep(30 * 1000);
		}

		card_intr = (*(volatile uint32_t *)(sdhci + SDHCI_INT_STATUS)
			>> 8) & 1u;

		/* SOCRAM tail trailer: window 19 (0x230000), F1 offset 0x7FF0
		 * = chip-internal 0x237FF0. Read 16 bytes ending at 0x237FFF. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x23u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x00u, NULL);
		rc_tail = diag_sdioCmd53Read(sdhci, 1, /*incr=*/1,
			/*reg_addr=*/0x7FF0u, /*block_count=*/1u, /*block_size=*/16u,
			socram_tail);

		/* DEFINITIVE fw-ready probe: read the SDIO-DEV core's
		 * tohostmailboxdata (SDIOD_CORE_BASE + 0x4C). brcmfmac/WHD treat
		 * HMB_DATA_FWREADY (0x0008) here as THE "firmware booted" signal —
		 * more reliable than HT/F2/CARD_INTR. For the 43455 the SDIOD core
		 * base is hypothesized at 0x18005000 (WHD maps the sibling 0x4373
		 * there, and our EROM walk has an unidentified core at 0x18005000;
		 * 0x18004000 is absent). Window=0x18000000 (L=0,M=0,H=0x18), so F1
		 * offset 0x504C reaches 0x1800504C. A sensible/non-0xff value also
		 * validates the base guess. */
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Au, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Bu, 0x00u, NULL);
		(void)diag_sdioCmd52(sdhci, 1, 1, 0x1000Cu, 0x18u, NULL);
		{
			uint32_t m0[4] = {0}, m1[4] = {0}, m2[4] = {0}, m3[4] = {0};
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x504Cu, 0u, m0);
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x504Du, 0u, m1);
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x504Eu, 0u, m2);
			(void)diag_sdioCmd52(sdhci, 0, 1, 0x504Fu, 0u, m3);
			hmb_data = (m0[0] & 0xffu) | ((m1[0] & 0xffu) << 8) |
				((m2[0] & 0xffu) << 16) | ((m3[0] & 0xffu) << 24);
		}
	}

	munmap(sdhci_page, _PAGE_SIZE);
	munmap(gpio_page, _PAGE_SIZE);

	r = snprintf(buf + off, cap - off,
		"enum: CMD5=%d/%d C=%d RCA=0x%04x CMD7=%d IORDY=0x%02x rdy=%d\n",
		rc_ocr, rc_claim,
		(int)((claim_resp[0] >> 31) & 1u),
		(unsigned)rca, rc_sel,
		(unsigned)(iordy_resp[0] & 0xff), rdy_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}
	(void)rc_iordy;

	r = snprintf(buf + off, cap - off,
		"fw_load: staged %u bytes across %d windows  HS=%d  worst rc_w=%d\n",
		bytes_written, window_idx, rc_hs, worst_rc_w);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"nvram: %zu bytes -> chip 0x%06x  rc_nvram_w=%d  HT_clk_csr=0x%02x (HT_AVAIL=0x80)\n",
		wifi_nvram_43455_len,
		(unsigned)(0x238000u - (uint32_t)wifi_nvram_43455_len),
		rc_nvram_w, (unsigned)ht_clk_csr);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"ARMCR4 IoCtrl pre=0x%02x  post=0x%02x  (expect pre=0x21 CPUHALT+clk, post=0x01 clk-only)\n",
		(unsigned)(rc_pre_resp[0] & 0xff),
		(unsigned)(rc_post_resp[0] & 0xff));
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"rstvec@addr0 readback: %02x %02x %02x %02x  vs fw[0..3]: %02x %02x %02x %02x  -> %s\n",
		rstvec_rb[0], rstvec_rb[1], rstvec_rb[2], rstvec_rb[3],
		wifi_fw_43455[0], wifi_fw_43455[1], wifi_fw_43455[2], wifi_fw_43455[3],
		(rstvec_rb[0] == wifi_fw_43455[0] && rstvec_rb[1] == wifi_fw_43455[1] &&
			rstvec_rb[2] == wifi_fw_43455[2] && rstvec_rb[3] == wifi_fw_43455[3])
			? "MATCH (vector placed at true backplane 0)"
			: "MISMATCH (addr-0 write landed elsewhere -- CR4 fetches garbage!)");
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	if (rc_r_pre == 0 && rc_r_post == 0) {
		pre_match = 0;
		post_match = 0;
		diff_count = 0;
		for (i = 0; i < (int)sizeof(pre_buf); ++i) {
			if (pre_buf[i] == wifi_fw_43455[i]) ++pre_match;
			if (post_buf[i] == wifi_fw_43455[i]) ++post_match;
			if (pre_buf[i] != post_buf[i]) ++diff_count;
		}
		r = snprintf(buf + off, cap - off,
			"SOCRAM[0..63] pre vs fw: %d/64 match (load check)\n",
			pre_match);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		r = snprintf(buf + off, cap - off,
			"SOCRAM[0..63] post vs fw: %d/64 match  pre-vs-post diff: %d/64 bytes\n",
			post_match, diff_count);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		r = snprintf(buf + off, cap - off,
			"  fw[0..7]   %02x %02x %02x %02x %02x %02x %02x %02x\n"
			"  pre[0..7]  %02x %02x %02x %02x %02x %02x %02x %02x\n"
			"  post[0..7] %02x %02x %02x %02x %02x %02x %02x %02x\n",
			wifi_fw_43455[0], wifi_fw_43455[1], wifi_fw_43455[2], wifi_fw_43455[3],
			wifi_fw_43455[4], wifi_fw_43455[5], wifi_fw_43455[6], wifi_fw_43455[7],
			pre_buf[0], pre_buf[1], pre_buf[2], pre_buf[3],
			pre_buf[4], pre_buf[5], pre_buf[6], pre_buf[7],
			post_buf[0], post_buf[1], post_buf[2], post_buf[3],
			post_buf[4], post_buf[5], post_buf[6], post_buf[7]);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		if (diff_count > 0) {
			r = snprintf(buf + off, cap - off,
				"  -> SOCRAM CHANGED after release: firmware appears to be running\n");
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
		else {
			r = snprintf(buf + off, cap - off,
				"  -> SOCRAM unchanged: firmware may not have started (need NVRAM?)\n");
			if (r > 0 && (size_t)r < cap - off) {
				off += r;
			}
		}
	}

	if (scan_changed_pts >= 0) {
		r = snprintf(buf + off, cap - off,
			"image-scan post vs fw (changed bytes/64 @ +off): "
			"+0x02000=%d +0x10000=%d +0x30000=%d +0x60000=%d +0x90000=%d +0x9C000=%d\n",
			scan_diff[0], scan_diff[1], scan_diff[2], scan_diff[3], scan_diff[4], scan_diff[5]);
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
		r = snprintf(buf + off, cap - off,
			"  -> %d/6 points changed => %s\n",
			scan_changed_pts,
			(scan_changed_pts > 0)
				? "CR4 IS EXECUTING (writing memory) -- gate is observability/early-stall"
				: "no memory writes anywhere -- fw genuinely not running (chase rstvec/activate)");
		if (r > 0 && (size_t)r < cap - off) {
			off += r;
		}
	}

	r = snprintf(buf + off, cap - off,
		"F2 enable: IOR=0x%02x ready=%s @iter=%d (F2_RDY=bit2 0x04)\n",
		f2_ready, ((f2_ready & 0x04u) != 0u) ? "YES" : "no", f2_ready_iters);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"SDIOD tohostmailboxdata=0x%08x -> %s (HMB_DATA_FWREADY=0x0008; SDIOD base hyp 0x18005000)\n",
		hmb_data,
		((hmb_data & 0x0008u) != 0u) ? "FWREADY set -- FIRMWARE BOOTED!"
			: ((hmb_data == 0xffffffffu || hmb_data == 0u) ? "0/0xff (no fw signal, or wrong SDIOD base)"
				: "nonzero but no FWREADY bit"));
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"CHIPCLKCSR poll: %02x %02x %02x %02x %02x %02x %02x %02x (HT_AVAIL=bit7 0x80)\n",
		chipclk_samples[0], chipclk_samples[1], chipclk_samples[2],
		chipclk_samples[3], chipclk_samples[4], chipclk_samples[5],
		chipclk_samples[6], chipclk_samples[7]);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	r = snprintf(buf + off, cap - off,
		"SDHCI CARD_INTR=%u  SOCRAM-tail rc=%d  trailer[12..15]=%02x %02x %02x %02x (blob trailer=%02x %02x %02x %02x)\n",
		card_intr, rc_tail,
		socram_tail[12], socram_tail[13], socram_tail[14], socram_tail[15],
		wifi_nvram_43455[wifi_nvram_43455_len - 4], wifi_nvram_43455[wifi_nvram_43455_len - 3],
		wifi_nvram_43455[wifi_nvram_43455_len - 2], wifi_nvram_43455[wifi_nvram_43455_len - 1]);
	if (r > 0 && (size_t)r < cap - off) {
		off += r;
	}

	{
		int fw_alive = 0;
		for (i = 0; i < 8; ++i) {
			if ((chipclk_samples[i] & 0x80u) != 0u) {
				fw_alive = 1;
			}
		}
		if (card_intr != 0u) {
			fw_alive = 1;
		}
		r = snprintf(buf + off, cap - off,
			"  -> fw_alive=%d %s\n", fw_alive,
			fw_alive ? "(HT_AVAIL or CARD_INTR asserted -- firmware booted!)"
				: "(no HT_AVAIL / no CARD_INTR -- firmware not confirmed running)");
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
		diag_wifiPowerCycle();

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


/* Framebuffer probe ('V') -- groundwork for a future /dev/fb0 driver.
 *
 * Queries the VideoCore graphmode that plo/firmware configured (the same
 * platformctl(pctl_get, pctl_graphmode) call pl011-tty's fbcon uses; it is a
 * general syscall, not tty-specific), mmaps the framebuffer from THIS arbitrary
 * userspace process, and NON-DESTRUCTIVELY verifies the read/write path: save a
 * few words at the bottom-right corner, write a known pattern, read it back,
 * compare, then restore the originals. Proves the userspace mmap + uncached
 * read/write coherence a /dev/fb0 driver would rely on, without taking over the
 * display or racing the fbcon console writer. The display-ownership and the
 * (Phoenix has no fbdev ABI) device-interface decisions are deferred to an
 * attended session -- see docs/notes/2026-06-05-fb0-attended-decisions.md. */
static int diag_format_fb(char *buf, size_t cap)
{
	platformctl_t pctl = { .action = pctl_get, .type = pctl_graphmode };
	volatile uint32_t *fb;
	void *fb_page;
	size_t fbsz, visible, testoff;
	uint32_t saved[16];
	uint32_t pattern[16];
	int rw_ok = 1;
	int i;
	int off = 0;

	if (platformctl(&pctl) != 0) {
		return snprintf(buf, cap, "PHX-DIAG/1 fb\nplatformctl(graphmode) failed\n.\n");
	}

	off += snprintf(buf + off, cap - off,
		"PHX-DIAG/1 fb\nfb: pa=0x%lx w=%u h=%u bpp=%u pitch=%u\n",
		(unsigned long)pctl.task.graphmode.framebuffer,
		(unsigned)pctl.task.graphmode.width,
		(unsigned)pctl.task.graphmode.height,
		(unsigned)pctl.task.graphmode.bpp,
		(unsigned)pctl.task.graphmode.pitch);

	if ((pctl.task.graphmode.framebuffer == 0u) || (pctl.task.graphmode.pitch == 0u)) {
		off += snprintf(buf + off, cap - off, "no framebuffer configured\n.\n");
		return off;
	}

	visible = (size_t)pctl.task.graphmode.pitch * (size_t)pctl.task.graphmode.height;
	fbsz = (visible + _PAGE_SIZE - 1u) & ~(size_t)(_PAGE_SIZE - 1u);

	fb_page = mmap(NULL, fbsz, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_UNCACHED | MAP_ANONYMOUS | MAP_PHYSMEM, -1,
		(off_t)pctl.task.graphmode.framebuffer);
	if (fb_page == MAP_FAILED) {
		off += snprintf(buf + off, cap - off, "mmap failed\n.\n");
		return off;
	}
	fb = (volatile uint32_t *)fb_page;

	/* Last 16 pixels (bottom-right): least likely to race the scrolling
	 * console, and restored within microseconds so the display is untouched. */
	testoff = (visible / sizeof(uint32_t)) - 16u;
	for (i = 0; i < 16; i++) {
		saved[i] = fb[testoff + i];
	}
	for (i = 0; i < 16; i++) {
		pattern[i] = 0xdeadbeefu ^ (uint32_t)((unsigned)i * 0x01010101u);
		fb[testoff + i] = pattern[i];
	}
	for (i = 0; i < 16; i++) {
		if (fb[testoff + i] != pattern[i]) {
			rw_ok = 0;
		}
	}
	for (i = 0; i < 16; i++) {
		fb[testoff + i] = saved[i]; /* restore -- non-destructive */
	}

	off += snprintf(buf + off, cap - off,
		"fb mmap rw %s (testoff_word=%u saved[0]=0x%08x wrote=0x%08x)\n.\n",
		(rw_ok != 0) ? "verified" : "FAILED",
		(unsigned)testoff, saved[0], pattern[0]);

	munmap(fb_page, fbsz);
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
		const ip4_addr_t *ip4 = netif_ip4_addr(n);
		const ip4_addr_t *gw4 = netif_ip4_gw(n);
		uint32_t ipw = ip4_addr_get_u32(ip4);
		uint32_t gww = ip4_addr_get_u32(gw4);
		unsigned flags = (unsigned)n->flags;

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

		/* ip/gw bytes are little-endian inside ip4_addr_t::addr on a
		 * little-endian host; format via ip4addr_ntoa via printf would
		 * pull in extra deps — manual byte unpack is fine and obvious. */
		/* DHCP state is in netif's client_data via dhcp_set_struct /
		 * the LWIP_NETIF_CLIENT_DATA_INDEX_DHCP slot. Standard lwip
		 * doesn't ship a one-liner predicate so peek directly. */
		struct dhcp *dhcp = netif_dhcp_data(n);

		r = snprintf(buf + off, cap - off,
			"netif: %c%c%u ip=%u.%u.%u.%u gw=%u.%u.%u.%u flags=0x%x%s%s%s",
			n->name[0], n->name[1], (unsigned)n->num,
			(unsigned)(ipw & 0xff), (unsigned)((ipw >> 8) & 0xff),
			(unsigned)((ipw >> 16) & 0xff), (unsigned)((ipw >> 24) & 0xff),
			(unsigned)(gww & 0xff), (unsigned)((gww >> 8) & 0xff),
			(unsigned)((gww >> 16) & 0xff), (unsigned)((gww >> 24) & 0xff),
			flags,
			(flags & NETIF_FLAG_UP) ? " UP" : "",
			(flags & NETIF_FLAG_LINK_UP) ? " LINK" : "",
			(dhcp != NULL) ? " DHCP" : "");
		if (r < 0 || (size_t)r >= cap - off) {
			break;
		}
		off += r;

		if (drv_len > 0) {
			r = snprintf(buf + off, cap - off, " %s\n", drv_stats);
		}
		else {
			r = snprintf(buf + off, cap - off, " (no per-driver stats)\n");
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
	else if (query == 'e') {
		len = diag_format_sdio_enum(body, DIAG_REPLY_MAX);
	}
	else if (query == 'f') {
		len = diag_format_sdio_f1(body, DIAG_REPLY_MAX);
	}
	else if (query == 'F') {
		len = diag_format_sdio_cores(body, DIAG_REPLY_MAX);
	}
	else if (query == 'E') {
		len = diag_format_sdio_erom(body, DIAG_REPLY_MAX);
	}
	else if (query == 'A') {
		len = diag_format_sdio_arm(body, DIAG_REPLY_MAX);
	}
	else if (query == 'S') {
		len = diag_format_sdio_socram(body, DIAG_REPLY_MAX);
	}
	else if (query == 'B') {
		len = diag_format_sdio_block(body, DIAG_REPLY_MAX);
	}
	else if (query == 'W') {
		len = diag_format_sdio_blockwrite(body, DIAG_REPLY_MAX);
	}
	else if (query == 'L') {
		len = diag_format_sdio_fwloadtest(body, DIAG_REPLY_MAX);
	}
	else if (query == 'M') {
		len = diag_format_sdio_fwwalk(body, DIAG_REPLY_MAX);
	}
	else if (query == 'I') {
		len = diag_format_sdio_fwload(body, DIAG_REPLY_MAX);
	}
	else if (query == 'H') {
		len = diag_format_sdio_hs(body, DIAG_REPLY_MAX);
	}
	else if (query == 'G') {
		len = diag_format_sdio_fwrelease(body, DIAG_REPLY_MAX);
	}
	else if (query == 'P') {
		len = diag_format_pcie_err(body, DIAG_REPLY_MAX);
	}
	else if (query == 'm') {
		len = diag_format_meminfo(body, DIAG_REPLY_MAX);
	}
	else if (query == 'D') {
		len = diag_format_devnodes(body, DIAG_REPLY_MAX);
	}
	else if (query == 'V') {
		len = diag_format_fb(body, DIAG_REPLY_MAX);
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
