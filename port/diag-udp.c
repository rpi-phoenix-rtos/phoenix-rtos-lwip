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
#include <stdlib.h>
#include <string.h>
#include <sys/threads.h>
#include <sys/time.h>
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
