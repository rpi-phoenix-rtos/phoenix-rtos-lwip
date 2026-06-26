/*
 * Phoenix-RTOS --- LwIP port
 *
 * GENET cacheable-RX integrity + throughput bench (Policy B, task #11)
 *
 * Copyright 2026 Phoenix Systems
 *
 * %LICENSE%
 *
 * Gated entirely behind GENET_RX_CACHEABLE: in the default build (flag 0) this
 * file compiles to nothing, so the proven uncached RX path and normal boots are
 * untouched.
 *
 * When the flag is 1 (orchestrator: -DGENET_RX_CACHEABLE=1) genet_rxcacheBench()
 * is spawned from main() after the netif comes up. It:
 *   1. connects (TCP) to the default gateway on GENET_RXCACHE_BENCH_PORT,
 *   2. streams bytes off the socket — which drags the full GENET RX DMA path
 *      through the cacheable pool + per-frame `dc ivac` maintenance,
 *   3. verifies every byte against a known pattern (byte k of the stream ==
 *      k & 0xFF), so a cache-coherency slip (stale line, missed invalidate)
 *      shows up as a mismatch rather than silent corruption,
 *   4. prints exactly one result line for the orchestrator to grep:
 *
 *        GENET-RXCACHE: ENABLED throughput=X.XX MB/s integrity=PASS/FAIL ...
 *
 * Host side (orchestrator), serve the pattern on the gateway:
 *   python3 -c 'import socket,sys
 *   s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 *   s.bind(("0.0.0.0",5099));s.listen(1)
 *   while True:
 *       c,_=s.accept();n=0
 *       try:
 *           buf=bytes(range(256))*256  # 64 KiB, byte k == k&0xFF
 *           while n < (64<<20):
 *               c.sendall(buf); n+=len(buf)
 *       except Exception: pass
 *       c.close()'
 */

#include "lwipopts.h"

#ifndef GENET_RX_CACHEABLE
#define GENET_RX_CACHEABLE 0
#endif

#if GENET_RX_CACHEABLE

#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/threads.h>
#include <sys/time.h>
#include <unistd.h>


#ifndef GENET_RXCACHE_BENCH_PORT
#define GENET_RXCACHE_BENCH_PORT 5099
#endif

/* Total bytes to pull before reporting. 32 MiB is enough to (a) outrun first-link
 * transients and (b) give a stable throughput number over a multi-second window. */
#ifndef GENET_RXCACHE_BENCH_BYTES
#define GENET_RXCACHE_BENCH_BYTES (32u * 1024u * 1024u)
#endif

#define GENET_RXCACHE_BENCH_CHUNK 4096u


/* 16 KB stack (no guard page on these): the bench calls deep into lwip_recv +
 * printf — keep generous margin (cf. #120/#152 8 KB pool-thread overflows). */
static uint32_t bench_stack[4096] __attribute__((aligned(16)));

/* Single-threaded bench: keep the 4 KB RX chunk off the stack. */
static uint8_t bench_buf[GENET_RXCACHE_BENCH_CHUNK];


static void genet_rxcacheBenchThread(void *arg)
{
	struct netif *netif = NULL;
	struct sockaddr_in sa;
	uint64_t total = 0;
	uint64_t mism = 0;
	uint32_t pat = 0; /* expected next byte == pat & 0xFF */
	time_t t0, t1;
	int fd, attempt;
	uint32_t gw;

	(void)arg;

	/* Wait for DHCP / link to settle and a non-zero gateway to appear.
	 * netif_default is set from the link-poll thread's dhcp callback SECONDS
	 * after main() spawns us, so re-read the live global every iteration —
	 * never cache it before it is populated. */
	for (attempt = 0; attempt < 60; ++attempt) {
		netif = netif_default;
		if (netif != NULL && !ip4_addr_isany_val(*netif_ip4_gw(netif)) &&
				!ip4_addr_isany_val(*netif_ip4_addr(netif))) {
			break;
		}
		usleep(1000 * 1000);
	}
	if (netif == NULL || ip4_addr_isany_val(*netif_ip4_gw(netif))) {
		printf("GENET-RXCACHE: ENABLED throughput=0.00 MB/s integrity=FAIL (no gateway)\n");
		endthread();
	}
	gw = ip4_addr_get_u32(netif_ip4_gw(netif));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = lwip_htons(GENET_RXCACHE_BENCH_PORT);
	sa.sin_addr.s_addr = gw;

	fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("GENET-RXCACHE: ENABLED throughput=0.00 MB/s integrity=FAIL (socket)\n");
		endthread();
	}

	if (lwip_connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("GENET-RXCACHE: ENABLED throughput=0.00 MB/s integrity=FAIL "
			"(connect gw=%u.%u.%u.%u:%u)\n",
			(unsigned)(gw & 0xFF), (unsigned)((gw >> 8) & 0xFF),
			(unsigned)((gw >> 16) & 0xFF), (unsigned)((gw >> 24) & 0xFF),
			GENET_RXCACHE_BENCH_PORT);
		lwip_close(fd);
		endthread();
	}

	gettime(&t0, NULL);
	while (total < GENET_RXCACHE_BENCH_BYTES) {
		int n = lwip_recv(fd, bench_buf, sizeof(bench_buf), 0);
		if (n <= 0) {
			break; /* peer closed or error: report what we got */
		}
		for (int i = 0; i < n; ++i) {
			if (bench_buf[i] != (uint8_t)(pat & 0xFFu)) {
				mism++;
			}
			pat++;
		}
		total += (uint64_t)n;
	}
	gettime(&t1, NULL);

	lwip_close(fd);

	/* CAVEAT: over TCP a coherency slip corrupts a frame -> bad checksum ->
	 * retransmit, so the bytes we finally read are correct and integrity reads
	 * PASS. On this path THROUGHPUT (collapsing far below ~8 MB/s) is the real
	 * coherency signal; integrity=PASS confirms no *uncorrected* corruption. */
	{
		uint64_t us = (uint64_t)(t1 - t0);
		/* MB/s = bytes / us  (bytes/us == MB/s since 1e6 us/s and 1e6 B/MB). */
		uint32_t mbps_i = 0, mbps_f = 0;
		if (us > 0) {
			uint64_t scaled = (total * 100u) / us; /* MB/s * 100 */
			mbps_i = (uint32_t)(scaled / 100u);
			mbps_f = (uint32_t)(scaled % 100u);
		}
		printf("GENET-RXCACHE: ENABLED throughput=%u.%02u MB/s integrity=%s "
			"(bytes=%llu mismatch=%llu)\n",
			mbps_i, mbps_f,
			(mism == 0 && total >= GENET_RXCACHE_BENCH_BYTES) ? "PASS" : "FAIL",
			(unsigned long long)total, (unsigned long long)mism);
	}

	/* A Phoenix thread must exit via endthread(), never by returning: beginthreadex
	 * installs no return trampoline, so the entry function's closing `ret` would pop
	 * the stack's 0x1e poison fill and fault (PC-alignment Exception #34, pc=far=
	 * 0x1e1e1e1e1e1e1e1e) — which crashed the lwip process right after this bench
	 * printed PASS. (All the other threads in this driver loop forever, so they
	 * never hit this; this one-shot bench is the only one that finishes.) */
	endthread();
}


/* Spawn the bench (called from main() only when GENET_RX_CACHEABLE is on). */
void genet_rxcacheBench(struct netif *netif)
{
	if (beginthread(genet_rxcacheBenchThread, 4, bench_stack,
			sizeof(bench_stack), netif) != 0) {
		printf("GENET-RXCACHE: ENABLED throughput=0.00 MB/s integrity=FAIL (thread)\n");
	}
}

#endif /* GENET_RX_CACHEABLE */
