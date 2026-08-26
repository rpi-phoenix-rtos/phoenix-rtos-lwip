/*
 * Phoenix-RTOS --- LwIP port
 *
 * BCM2711 GENET v5 Ethernet driver (Pi 4, BCM54213PE PHY over RGMII)
 *
 * Copyright 2026 Phoenix Systems
 *
 * %LICENSE%
 *
 * Tier 5 scope:
 *   - MMIO map, GENET v5 silicon ID validation, UMAC reset
 *   - MDIO bus exposed to ephy.c (BCM54213PE)
 *   - RGMII / SYS_PORT_CTRL / RBUF / DMA init per Linux + Circle refs
 *   - TX: single-slot synchronous polled descriptor (one in-flight frame
 *     at a time; the linkoutput call returns only after the HW consumer
 *     index advances)
 *   - RX: 256-BD ring, each BD armed from a pool of GENET_RX_POOL_SLOTS
 *     (256 BDs + 256 in-flight slack) UNIQUE pinned buffers managed by a
 *     free-list (no aliasing; an earlier build aliased only 16 buffers and
 *     corrupted under back-to-back RX — see the pool comment below),
 *     INTRL2_0_RX_DMA_DONE wakes a service thread that drains BDs into
 *     lwip-owned pbufs and hands them to tcpip_input
 *   - Link state: 1 Hz polling thread (the BCM54213PE PHY's INT_B pin
 *     is not routed to a GIC SPI on the Pi 4 board, so MDIO polling is
 *     the only portable option here — TODO(TD-Eth-LinkIRQ) revisit if
 *     a future board variant exposes the line)
 *
 * Caveats still in place:
 *   - MAC source is the VideoCore mailbox property tag 0x10003
 *     (GET_BOARD_MAC). The previous locally-administered fallback is
 *     used only if the mailbox call fails; we set UMAC_CMD.PROMISC
 *     only on that fallback path.
 *
 * References (BEHAVIORAL only — fresh-code per CLAUDE.md
 * upstreamability guidance):
 *   - Linux drivers/net/ethernet/broadcom/genet/bcmgenet.c
 *   - U-Boot drivers/net/bcmgenet.c (BCM2711 path)
 *   - Circle lib/bcm54213.cpp + bcm54213.h
 *   - FreeBSD sys/arm/broadcom/bcm2835/bcm2835_genet.c
 *   - docs/research/ethernet-genet.md, ethernet-genet-non-linux.md
 *   - docs/notes/2026-05-24-eth-tier0-scout.md
 */
#include "netif-driver.h"
#include "physmmap.h"
#include "ephy.h"
#include "bcm-genet-regs.h"
#include "board_config.h"

#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/dhcp.h"
#include "lwip/tcpip.h"
#include "lwip/priv/tcpip_priv.h" /* LOCK_TCPIP_CORE / UNLOCK_TCPIP_CORE (RX-input batching) */
#include "netif/ethernet.h"       /* ethernet_input (un-locked inner RX-input fn) */

#include <sys/interrupt.h>
#include <sys/mman.h>
#include <sys/threads.h>
#include <sys/time.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define GENET_MMIO_SIZE   0x10000u  /* 64 KiB */
#define MDIO_TIMEOUT_US   20000u    /* xHCI MDIO max per Linux bcmmii */


/*
 * Policy B — cacheable (streaming-DMA) RX path. DEFAULT-OFF.
 *
 * The proven RX path (this flag = 0) DMAs into an UNCACHED dmammap pool: zero
 * cache maintenance, but the whole TCP/IP recv chain then touches every payload
 * byte uncached, which is slow. When this flag is 1 the RX pool is allocated
 * WRITE-BACK CACHEABLE (dmammap_cached) and the driver does Linux-style
 * per-frame streaming-DMA cache maintenance:
 *   - dma_sync_for_device: clean+invalidate a slot's cache lines BEFORE arming
 *     its BD (so no dirty line can write back over a frame the device is about
 *     to DMA),
 *   - dma_sync_for_cpu: clean+invalidate a slot's cache lines BEFORE the CPU
 *     reads a received frame.
 * Per-line ops use `dc civac` — the only EL0-legal invalidate-bearing op (the
 * UCI set is CVAU/CVAC/CVAP/CIVAC + IC IVAU; pure `dc ivac` is EL1-only and TRAPS
 * at EL0, which is why an earlier `dc ivac` version killed RX entirely — see
 * genet_dcacheCleanInvalRx). Each pool slot is GENET_MAX_FRAME (2048) bytes — a
 * cache-line multiple — so a whole-slot op never touches a neighbour's lines
 * (the classic streaming-DMA buffer-clobber bug is avoided by construction).
 *
 * NEEDS-CAREFUL-HW-REVIEW: a cache-coherency mistake here corrupts RX silently.
 * Keep this OFF for normal boots; enable only for the integrity bench
 * (-DGENET_RX_CACHEABLE=1) where genet-rxcache-bench verifies byte-correctness.
 */
#ifndef GENET_RX_CACHEABLE
#define GENET_RX_CACHEABLE 1  /* write-back cacheable RX pool + per-frame cache maintenance
                               * (genet_dcacheCleanInvalRx) — the design Linux/NetBSD/FreeBSD use.
                               * Faster than uncached (raw TCP 260→300 Mbit/s, NFS 16.9→18.9 MB/s)
                               * because lwip's checksum + the socket recv-copy read cached memory.
                               * HW-VALIDATED 2026-08-26 (requires LWIP_TCPIP_CORE_LOCKING_INPUT):
                               *   Gate 1 data-integrity: sha256 of a 128MB NFS read == host, bit-
                               *     exact, drop=0/rbuf_ovfl=0/copyfb=0.
                               *   Gate 2 GPU+net: glamor X up, NO FB corruption observed on the
                               *     (idle) WindowMaker desktop during concurrent NFS load — kills the
                               *     scanout-PA-overlap + gross-coherency stories. (Continuous GPU
                               *     rendering-under-load + net not yet stressed; the V3D BIN/RENDER
                               *     binner wedges seen are PRE-EXISTING — an uncached control
                               *     reproduced them identically — unrelated to RX caching.)
                               * The old "cacheable corrupts the GPU FB / NFS ERANGE" warnings were
                               * REFUTED here — they were tied to the pre-core-locking mbox input
                               * path. Override to 0 with `make GENET_RX_CACHEABLE=0` to roll back. */
#endif

/* TEMP diag: per-frame NFS/TCP RX logging in the drain path to discriminate
 * delivered-but-corrupt from before-ring loss (gigabit NFS triage). Revert to 0. */
#ifndef GENET_RXFRAME_LOG
#define GENET_RXFRAME_LOG 0
#endif

/* Early guard: GENET_RXSTATS_LOG is referenced by the state struct + drain
 * profiling below (well above its console-print site). Default it here so
 * -Werror=undef is satisfied in the stock build (the later #ifndef is a
 * harmless no-op once this defines it). */
#ifndef GENET_RXSTATS_LOG
#define GENET_RXSTATS_LOG 0
#endif

/* RX-input core-lock batching (gigabit Option C, lever #1). Under
 * LWIP_TCPIP_CORE_LOCKING_INPUT, netif->input (=tcpip_input) locks+unlocks the
 * TCPIP core lock PER PACKET; on this microkernel a mutex op is a ~2.25 us
 * syscall (~4.5 us/pair, HW-measured), and RXPROF showed ~39.5 us/frame of RX
 * cost dominated by ~6 such lock pairs/frame. Hold the core lock ONCE across a
 * drain burst and call ethernet_input directly per frame, removing the per-frame
 * core-lock pair. Same lock + same serialization (held marginally longer); the
 * call chain under the lock (ethernet_input -> ... -> tcp_output -> genet TX) is
 * exactly what already runs under the per-frame lock today, so no new deadlock
 * class. The value is the CHUNK size: the lock is released+reacquired every N
 * frames so a large backlog can't hold it unboundedly (releasing between frames
 * is safe -- no lwip state is carried across the frame boundary). 0 = disabled
 * (stock per-frame netif->input). DEFAULT-OFF until HW-validated; enable/tune
 * with `make GENET_RX_INPUT_BATCH=<N>`. Requires LWIP_TCPIP_CORE_LOCKING_INPUT. */
#ifndef GENET_RX_INPUT_BATCH
#define GENET_RX_INPUT_BATCH 0
#endif

#if (GENET_RX_INPUT_BATCH > 0) && LWIP_TCPIP_CORE_LOCKING_INPUT
#define GENET_RX_INPUT(netif, p) ethernet_input((p), (netif))
#define GENET_RX_BURST_LOCK()    LOCK_TCPIP_CORE()
#define GENET_RX_BURST_UNLOCK()  UNLOCK_TCPIP_CORE()
#else
#define GENET_RX_INPUT(netif, p) ((netif)->input((p), (netif)))
#define GENET_RX_BURST_LOCK()    ((void)0)
#define GENET_RX_BURST_UNLOCK()  ((void)0)
#endif

/* TEST: adopt the VideoCore firmware's already-trained gigabit PHY — skip the PHY
 * hard reset here + the soft reset/autoneg-restart in ephy.c. Revert to 0. */
#ifndef GENET_PHY_ADOPT_FW
#define GENET_PHY_ADOPT_FW 0
#endif

/* irq-thread poll-drain backstop interval (us): the RX interrupt for a frame
 * arriving right after a TX is empirically lost at gigabit, so the thread polls
 * the RX ring at least this often and drains any stranded frame. Bounds RX
 * latency to this interval when the interrupt is missed. */
#ifndef GENET_RX_POLL_US
#define GENET_RX_POLL_US 2000u
#endif

/*
 * RX ring depth. The HW default-queue ring is GENET_TOTAL_DESC (256) BDs and
 * the BUF_SIZE/END_ADDR are programmed for that full count. We MUST back every
 * BD with its own unique buffer: an earlier build allocated only 16 unique
 * buffers and aliased BDs 16..255 cyclically back onto them, but that defeats
 * the ring's flow control — once the HW producer gets >16 BDs ahead of the
 * drain thread it overwrites a not-yet-drained aliased
 * buffer, corrupting frames. On the wire that shows up as packet loss +
 * reordering, which collapses the server's TCP cwnd to 1 (confirmed via host
 * `ss -ti`: bytes_retrans ~2.5%, cwnd:1) and caps NFS throughput far below the
 * link. 16 was originally chosen only because 256 *separate* dmammap()
 * MAP_CONTIGUOUS calls stalled the allocator at startup; we now allocate the
 * whole pool in ONE contiguous dmammap and carve it, so all 256 BDs get unique
 * buffers without tripping that cliff.
 */
#define GENET_RX_SLOTS    GENET_TOTAL_DESC


static err_t genet_linkOutput(struct netif *netif, struct pbuf *p);
static void genet_rxbufFree(struct pbuf *p);


/*
 * Zero-copy RX: the drain hands the DMA buffer straight to lwip wrapped in a
 * custom pbuf (no per-frame memcpy/malloc) and refills the BD from a free list.
 * lwip owns the buffer until tcpip_input's thread frees the pbuf, which calls
 * genet_rxbufFree() to return it to the free list. So we need MORE buffers than
 * the 256 BDs: 256 armed + a slack pool for frames in flight up the stack
 * (sized from TCPIP_MBOX_SIZE + recv mailboxes). When the free list runs dry the
 * drain falls back to the original copy path, so a shortfall degrades to slow,
 * never to a wedged ring or buffer reuse. */
#define GENET_RX_POOL_SLOTS  (GENET_TOTAL_DESC + 256u)   /* 256 BDs + in-flight slack */

typedef struct genet_rxbuf {
	struct pbuf_custom pc;   /* MUST be first: custom_free gets &pc == &pc.pbuf */
	void *state;             /* genet_state_t * (void* to dodge the fwd-decl) */
	uint16_t idx;            /* this buffer's index in the pool */
} genet_rxbuf_t;

typedef struct {
	addr_t dev_phys_addr;
	volatile uint32_t *mmio;
	struct netif *netif;

	uint8_t mac[6];
	bool mac_is_fallback;

	int mdio_bus;
	eth_phy_state_t phy;

	int irq_general;  /* GIC IRQ for INTRL2_0 (SPI 157 = abs 189) */
	int irq_ring;     /* GIC IRQ for INTRL2_1 (SPI 158 = abs 190; unused) */

	int last_link_up;
	int last_speed;
	int last_duplex;
	int dhcp_started;
	/* 8 KB — shallow MDIO poll loop; doubled from 4 KB for uniformity (#152). */
	uint32_t link_poll_stack[2048] __attribute__((aligned(16)));

	/* TX: single DMA buffer, ring of 256 BDs in MMIO. */
	void *tx_buf;
	addr_t tx_buf_phys;
	handle_t tx_lock;
	uint32_t tx_index;       /* 0..GENET_TOTAL_DESC-1 — BD index in MMIO */
	uint32_t tx_prod_index;  /* 16-bit running counter the HW compares to CONS_INDEX */
	unsigned long tx_pkts;
	unsigned long tx_timeouts;

	/* RX: per-slot buffers + IRQ-driven service thread. The BD's address
	 * is programmed once at init — HW writes received frames into the
	 * same physical buffer each time the BD comes back around. The buffers
	 * are one contiguous pool (rx_pool) carved into GENET_TOTAL_DESC slices. */
	void *rx_pool;            /* single contiguous dmammap for ALL pool buffers */
	addr_t rx_pool_phys;
	void *rx_bufs[GENET_RX_POOL_SLOTS];      /* VA of each pool buffer */
	addr_t rx_bufs_phys[GENET_RX_POOL_SLOTS];/* PA of each pool buffer */
	uint16_t rx_bd_buf[GENET_TOTAL_DESC];    /* which pool buffer each BD is armed with */
	genet_rxbuf_t rx_pc[GENET_RX_POOL_SLOTS];/* custom-pbuf wrapper per pool buffer */
	uint16_t rx_free[GENET_RX_POOL_SLOTS];   /* free-list (stack of pool-buffer indices) */
	int rx_free_top;                         /* # entries on the free list */
	handle_t rx_free_lock;                   /* drain pops, custom-free pushes (cross-thread) */
	unsigned long rx_zerocopy;               /* frames handed up zero-copy */
	unsigned long rx_copyfallback;           /* frames that fell back to the copy path */
	uint32_t rx_index;       /* 0..GENET_TOTAL_DESC-1 — BD index in MMIO */
	uint32_t rx_c_index;     /* SW's view, mirrors RDMA_RING_CONS_INDEX */
	unsigned long rx_pkts_seen;
	unsigned long rx_pkts_dropped;
	unsigned long rx_rearm_stranded;   /* frames caught by the post-unmask re-drain */
	unsigned long rx_pollrescue;       /* frames caught by the irq-thread poll backstop (lost-IRQ) */
	unsigned long rx_polls;            /* irq-thread condWait timeouts (poll backstop invocations) */
#if GENET_RXSTATS_LOG
	/* Throughput-profiling accumulators (GENET_RXSTATS_LOG only): attribute the
	 * per-frame drain cost. input_us/input_calls = mean us in netif->input()
	 * (tcpip mbox post+wake); txspin_us/tx_spin_calls = mean us busy-polling TX
	 * completion; drain_wakes + rx_pkts_seen = frames-per-drain-wake. */
	unsigned long long input_us;
	unsigned long input_calls;
	unsigned long long txspin_us;
	unsigned long tx_spin_calls;
	unsigned long drain_wakes;
#endif

	/* IRQ plumbing: handler runs in interrupt context, masks the level-2
	 * source bits it's about to service, signals irq_cond; irq_thread
	 * drains the affected rings and re-unmasks before going back to sleep. */
	handle_t irq_lock;
	handle_t irq_cond;
	handle_t irq_handle;
	uint32_t irq_events;
	/* 16 KB (#152): the IRQ thread drains the RX ring into pbuf/netif input;
	 * bumped from 8 KB for margin -- 8 KB is the exact size that overflowed the
	 * SD pool thread in #120, and this stack (like all here) has no guard page. */
	uint32_t irq_stack[4096] __attribute__((aligned(16)));
} genet_state_t;


#define genet_printf(state, fmt, ...) \
	printf("lwip: genet@%08x: " fmt "\n", (unsigned)(state)->dev_phys_addr, ##__VA_ARGS__)


/* --- MMIO accessors --------------------------------------------- */

static inline uint32_t genet_read(genet_state_t *state, uint32_t off)
{
	return *(volatile uint32_t *)((volatile uint8_t *)state->mmio + off);
}


static inline void genet_write(genet_state_t *state, uint32_t off, uint32_t val)
{
	*(volatile uint32_t *)((volatile uint8_t *)state->mmio + off) = val;
}


#if GENET_RX_CACHEABLE
/*
 * Clean+invalidate the D-cache lines covering [va, va+len) by VA (`dc civac`):
 * write back any dirty copy then drop the line, so (RX-complete -> read) the CPU
 * fetches what the device DMA'd from RAM, and (before arming a BD) no dirty line
 * can later evict over the device's DMA.
 *
 * IMPORTANT — must be `dc civac`, NOT `dc ivac`: this driver runs at EL0, and only
 * SCTLR_EL1.UCI's set is EL0-legal — DC CVAU/CVAC/CVAP/CIVAC + IC IVAU. The pure
 * invalidate `DC IVAC` is EL1-only; issuing it at EL0 TRAPS, which silently killed
 * the whole RX path (no frames drained -> no DHCP lease) the first time this landed.
 * (The kernel hal_cpuInvalDataCache uses `dc ivac` because it runs at EL1; the
 * _init.S:589 comment that lists "ivac" as UCI-enabled is wrong.) `civac` is
 * functionally correct at both our sync points: before a read no frame line is
 * CPU-dirty yet (the 2 ETH-pad bytes are written afterwards), so the clean is a
 * no-op and the invalidate does the work; before arming, the clean flushes the
 * spare's stale lines to RAM and the incoming frame simply DMAs over them.
 *
 * Callers always pass a whole GENET_MAX_FRAME slot, whose base is GENET_MAX_FRAME
 * (a cache-line multiple) past a page-aligned pool — so start and end are already
 * line-aligned and the op never reaches a neighbouring buffer. The explicit
 * round-down/round-up below keeps that safe even if a partial range is ever passed. */
static inline void genet_dcacheCleanInvalRx(void *va, size_t len)
{
	uint64_t ctr;
	uintptr_t line, start, end;

	__asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
	line = (uintptr_t)4 << ((ctr >> 16) & 0xfu);  /* CTR_EL0.DminLine: log2(words) */

	start = (uintptr_t)va & ~(line - 1u);
	end = ((uintptr_t)va + len + line - 1u) & ~(line - 1u);

	__asm__ volatile("dsb sy" ::: "memory");
	for (; start < end; start += line) {
		__asm__ volatile("dc civac, %0" : : "r"(start) : "memory");
	}
	__asm__ volatile("dsb sy" ::: "memory");
}
#endif /* GENET_RX_CACHEABLE */


/* --- Reset / MAC / UMAC ----------------------------------------- */

static int genet_validateRevision(genet_state_t *state)
{
	uint32_t rev = genet_read(state, SYS_REV_CTRL);
	uint32_t major = (rev & SYS_REV_CTRL_MAJOR_MASK) >> SYS_REV_CTRL_MAJOR_SHIFT;
	uint32_t minor = (rev & SYS_REV_CTRL_MINOR_MASK) >> SYS_REV_CTRL_MINOR_SHIFT;

	/* GENETv5 silicon increment major is 6; some Pi 4-B revs report 7.
	 * Anything in {5, 6, 7} maps to the v5 register layout per Circle
	 * and U-Boot. Reject older versions (we don't have the v4/v3 offset
	 * tables). */
	genet_printf(state, "SYS_REV_CTRL=0x%08x (major=%u minor=%u)", rev, major, minor);

	if (major < 5 || major > 7) {
		genet_printf(state, "unsupported GENET major rev %u", major);
		return -ENODEV;
	}

	return 0;
}


static void genet_readMac(genet_state_t *state)
{
	uint32_t hi = genet_read(state, UMAC_MAC0);
	uint32_t lo = genet_read(state, UMAC_MAC1);

	/* UMAC_MAC0 holds MAC bytes [0..3] (MSB-first), UMAC_MAC1 holds bytes [4..5]
	 * in its low half-word — matches the Linux bcmgenet layout. */
	state->mac[0] = (hi >> 24) & 0xFFu;
	state->mac[1] = (hi >> 16) & 0xFFu;
	state->mac[2] = (hi >> 8) & 0xFFu;
	state->mac[3] = hi & 0xFFu;
	state->mac[4] = (lo >> 8) & 0xFFu;
	state->mac[5] = lo & 0xFFu;
}


static void genet_writeMac(genet_state_t *state)
{
	uint32_t hi = ((uint32_t)state->mac[0] << 24) |
		((uint32_t)state->mac[1] << 16) |
		((uint32_t)state->mac[2] << 8) |
		(uint32_t)state->mac[3];
	uint32_t lo = ((uint32_t)state->mac[4] << 8) | (uint32_t)state->mac[5];

	genet_write(state, UMAC_MAC0, hi);
	genet_write(state, UMAC_MAC1, lo);
}


/* --- VideoCore mailbox: GET_BOARD_MAC (property tag 0x10003) ---- */

#if defined(RPI_MAILBOX_BASE_ADDRESS)

#include <libvcmbox.h>

#define VC_PROP_GET_BOARD_MAC 0x00010003u


/* Read the board MAC over the VideoCore property mailbox, routed through the
 * serializing rpi4-vcmbox server (/dev/vcmbox) — the BCM2711 FIFO has no
 * hardware arbitration, so every mailbox user must go through the server rather
 * than drive the FIFO directly. GET_BOARD_MAC returns TWO value words: word 0 =
 * MAC bytes [0..3], word 1 = MAC bytes [4..5]+pad. On this little-endian target
 * a byte-copy of the two words yields the firmware's on-wire byte order
 * (identical to the previous raw-FIFO reader, which copied from &msg[5]). */
static int genet_mboxGetMac(uint8_t out[6])
{
	uint32_t macWords[2] = { 0, 0 };
	int rc = vcmbox_call(VC_PROP_GET_BOARD_MAC, 8u, NULL, 0u, macWords, 2u);

	if (rc != 0) {
		return rc;
	}

	memcpy(out, macWords, 6);
	return 0;
}

#else  /* !RPI_MAILBOX_BASE_ADDRESS */

static int genet_mboxGetMac(uint8_t out[6])
{
	(void)out;
	return -ENOTSUP;
}

#endif


static void genet_dmaDisable(genet_state_t *state)
{
	/* Linux bcmgenet_{rdma,tdma}_disable: clear DMA_EN and the per-ring
	 * enable bitmask in DMA_CTRL, then poll DMA_STATUS until those same
	 * bits show as set (the status register reports "this ring stopped"
	 * by asserting the bit, inverted from the CTRL register meaning).
	 *
	 * The bootloader's "GENET STOP: 0" leaves the block in a state that
	 * we have to walk through before initializing fresh — without this,
	 * RX_EN appears to be set but the data path silently drops frames. */
	uint32_t ring_mask = (1u << (GENET_DEFAULT_RING + 1)) - 1u;
	uint32_t full_mask = (ring_mask << GENET_TDMA_CTRL_RBUF_EN_LSB) |
		GENET_TDMA_CTRL_TDMA_EN;
	time_t now, deadline;

	for (int dma = 0; dma < 2; ++dma) {
		uint32_t base = (dma == 0) ?
			GENET_TDMA_REGS_OFF : GENET_RDMA_REGS_OFF;
		uint32_t reg = genet_read(state, base + GENET_TDMA_CTRL);
		reg &= ~full_mask;
		genet_write(state, base + GENET_TDMA_CTRL, reg);

		gettime(&now, NULL);
		deadline = now + GENET_DMA_TIMEOUT_US;
		for (;;) {
			uint32_t st = genet_read(state, base + GENET_TDMA_STATUS);
			if ((st & full_mask) == full_mask) {
				break;
			}
			gettime(&now, NULL);
			if (now >= deadline) {
				genet_printf(state,
					"DMA disable timeout (%s base=0x%x status=0x%08x)",
					dma == 0 ? "TDMA" : "RDMA", base, st);
				break;
			}
			usleep(10);
		}
	}
}


static int genet_resetUmac(genet_state_t *state)
{
	/* Reset sequence matches Circle's reset_umac and FreeBSD if_genet:
	 * 1. Disable TX/RX.
	 * 2. Reset RX/TX datapath buffers (SYS_RBUF_FLUSH_CTRL / TBUF).
	 * 3. Assert UMAC_CMD.SW_RESET | LCL_LOOP_EN, wait, clear.
	 * 4. Clear flush bits.
	 *
	 * Steps 2 and 4 quiesce the FIFOs around the MAC reset so packets
	 * in flight don't trigger spurious errors when CMD_RX/TX_EN comes
	 * back. */

	uint32_t cmd = genet_read(state, UMAC_CMD);
	cmd &= ~(CMD_RX_EN | CMD_TX_EN);
	genet_write(state, UMAC_CMD, cmd);

	genet_write(state, SYS_RBUF_FLUSH_CTRL, SYS_BUF_FLUSH_RESET);
	usleep(10);
	genet_write(state, SYS_RBUF_FLUSH_CTRL, 0);

	genet_write(state, UMAC_CMD, CMD_SW_RESET | CMD_LCL_LOOP_EN);
	usleep(2);
	genet_write(state, UMAC_CMD, 0);
	usleep(2);

	genet_write(state, SYS_TBUF_FLUSH_CTRL, 0);
	genet_write(state, SYS_RBUF_FLUSH_CTRL, 0);

	return 0;
}


/* --- MDIO bus --------------------------------------------------- */

static int genet_mdioWait(genet_state_t *state)
{
	time_t now, deadline;
	uint32_t v;

	gettime(&now, NULL);
	deadline = now + MDIO_TIMEOUT_US;

	for (;;) {
		v = genet_read(state, UMAC_MDIO_CMD);
		if ((v & MDIO_START_BUSY) == 0) {
			return 0;
		}
		gettime(&now, NULL);
		if (now >= deadline) {
			return -ETIMEDOUT;
		}
		usleep(10);
	}
}


static uint16_t genet_mdioRead(void *arg, unsigned addr, uint16_t reg)
{
	genet_state_t *state = arg;
	uint32_t cmd;

	cmd = MDIO_CMD_RD |
		((addr & 0x1Fu) << MDIO_PMD_SHIFT) |
		((reg & 0x1Fu) << MDIO_REG_SHIFT);

	genet_write(state, UMAC_MDIO_CMD, cmd);
	genet_write(state, UMAC_MDIO_CMD, cmd | MDIO_START_BUSY);

	if (genet_mdioWait(state) < 0) {
		genet_printf(state, "MDIO read addr=%u reg=%u timeout", addr, reg);
		return 0xFFFFu;
	}

	return (uint16_t)(genet_read(state, UMAC_MDIO_CMD) & MDIO_DATA_MASK);
}


static void genet_mdioWrite(void *arg, unsigned addr, uint16_t reg, uint16_t val)
{
	genet_state_t *state = arg;
	uint32_t cmd;

	cmd = MDIO_CMD_WR |
		((addr & 0x1Fu) << MDIO_PMD_SHIFT) |
		((reg & 0x1Fu) << MDIO_REG_SHIFT) |
		(uint32_t)val;

	genet_write(state, UMAC_MDIO_CMD, cmd);
	genet_write(state, UMAC_MDIO_CMD, cmd | MDIO_START_BUSY);

	if (genet_mdioWait(state) < 0) {
		genet_printf(state, "MDIO write addr=%u reg=%u timeout", addr, reg);
	}
}


static int genet_mdioSetup(void *arg, unsigned max_khz, unsigned min_hold_ns, unsigned opt_preamble)
{
	(void)arg;
	(void)max_khz;
	(void)min_hold_ns;
	(void)opt_preamble;

	/* GENET MDIO clock divides the bridge clock automatically — no
	 * software-visible MDC frequency control on the v5 IP block. */
	return 0;
}


static const mdio_bus_ops_t genet_mdio_ops = {
	.setup = genet_mdioSetup,
	.read = genet_mdioRead,
	.write = genet_mdioWrite,
};


/* --- PHY reset + RGMII configuration ---------------------------- */

__attribute__((unused)) static void genet_phyHardReset(genet_state_t *state)
{
	/* Strobe EXT_GPHY_RESET low/high. The BCM54213PE on Pi 4 takes its
	 * hard reset off the GENET block's EXT_GPHY_CTRL register, not a
	 * separate GPIO. Linux's bcmgenet_phy_reset and Circle's mii_probe
	 * follow the same shape. */
	uint32_t ext = genet_read(state, EXT_GPHY_CTRL);
	ext |= EXT_GPHY_RESET;
	genet_write(state, EXT_GPHY_CTRL, ext);
	usleep(10);  /* >= 10 us reset assertion */
	ext &= ~EXT_GPHY_RESET;
	genet_write(state, EXT_GPHY_CTRL, ext);

	/* PHY needs >= 200 us to come out of reset before MDIO is reliable.
	 * BCM54213PE datasheet specifies 100 us; double it for margin. */
	usleep(200);
}


static void genet_configRgmii(genet_state_t *state)
{
	/* GENET defaults SYS_PORT_CTRL to internal-EPHY (0) — it never
	 * routes data to the external BCM54213PE until we change it. This
	 * is the missing piece behind the Tier 3 "TX completes but tcpdump
	 * sees nothing" symptom. U-Boot's bcmgenet_interface_set does the
	 * same write for RGMII / RGMII_RXID phy modes. */
	genet_write(state, SYS_PORT_CTRL, PORT_MODE_EXT_GPHY);

	/* Pi 4 DT sets phy-mode = "rgmii-rxid": clearing ID_MODE_DIS enables the
	 * GENET MAC's internal *TX* clock delay (the RX delay is added PHY-side —
	 * see ephy_bcm54213pe_configClockDelay). TX delay may also come from PCB traces.
	 *
	 * OOB_DISABLE must be SET: that tells the MAC to take link state
	 * from RGMII_LINK (which we write below) instead of the out-of-band
	 * pins from the PHY. Without this bit the MAC silently treats the
	 * link as down and drops every received frame even though TX
	 * (which only needs RGMII_MODE_EN) still works. This was the cause
	 * of the Tier 3 RDMA_PROD_INDEX-stuck-at-0 symptom; matches Linux's
	 * bcmgenet_setup_rgmii / Circle's mii_config exactly. */
	uint32_t v = genet_read(state, EXT_RGMII_OOB_CTRL);

	/* TEST: match the VideoCore firmware's proven-working gigabit config, which
	 * CLEARS OOB_DISABLE (dumped: fw oob low-byte=0x50, i.e. RGMII_LINK|RGMII_MODE_EN
	 * only; Phoenix was setting 0x70 = +OOB_DISABLE). With OOB_DISABLE clear the MAC
	 * tracks link/status from the RGMII in-band signal the PHY drives, instead of the
	 * static RGMII_LINK register. Suspected cause of the gigabit post-TX RX-drop
	 * (frames vanish before the MAC, no FCS): the static-link path mis-handles the RX
	 * stream after a TX. (The old comment claimed OOB_DISABLE must be SET or RX dies
	 * with PROD stuck at 0 — but the firmware clearing it receives fine on this exact
	 * silicon, so that was context-specific.) Also matches U-Boot's bcmgenet. */
	v |= RGMII_LINK | RGMII_MODE_EN;
	v &= ~(ID_MODE_DIS | OOB_DISABLE);

	genet_write(state, EXT_RGMII_OOB_CTRL, v);
}


/* --- TX ring + UMAC speed configuration (Tier 2) --------------- */

static void genet_initTxRing(genet_state_t *state)
{
	uint32_t ring_off = GENET_TX_RINGS_OFF + GENET_DEFAULT_RING * GENET_DMA_RING_SIZE;
	uint32_t cons;

	/* Burst size — 8 64-bit words; matches U-Boot's DMA_MAX_BURST_LENGTH. */
	genet_write(state, GENET_TDMA_REGS_OFF + GENET_TDMA_SCB_BURST_SIZE,
		GENET_DMA_DEFAULT_BURST);

	/* Ring slice: spans the full BD area (0 .. TOTAL_DESC*3 - 1 words). */
	genet_write(state, ring_off + GENET_TDMA_RING_START_ADDR, 0);
	genet_write(state, ring_off + GENET_TDMA_RING_READ_PTR, 0);
	genet_write(state, ring_off + GENET_TDMA_RING_WRITE_PTR, 0);
	genet_write(state, ring_off + GENET_TDMA_RING_END_ADDR,
		(GENET_TOTAL_DESC * GENET_DMA_DESC_SIZE / 4u) - 1u);

	/* Match SW counters to whatever the hardware says CONS is. The hardware
	 * keeps an internal 16-bit running count of consumed descriptors; we
	 * mirror it so our first PROD_INDEX write is correctly ordered. */
	cons = genet_read(state, ring_off + GENET_TDMA_RING_CONS_INDEX);
	genet_write(state, ring_off + GENET_TDMA_RING_PROD_INDEX, cons);
	state->tx_prod_index = cons;
	state->tx_index = cons % GENET_TOTAL_DESC;

	/* Ring buffer size: <descriptor count><<16 | <per-slot bytes>. */
	genet_write(state, ring_off + GENET_TDMA_RING_BUF_SIZE,
		(GENET_TOTAL_DESC << 16) | (GENET_MAX_FRAME & 0xFFFFu));

	/* Mbuf-done threshold: 1 — fire the (yet-unused) IRQ on each packet. */
	genet_write(state, ring_off + GENET_TDMA_RING_MBUF_DONE, 1);
	genet_write(state, ring_off + GENET_TDMA_RING_FLOW_PERIOD, 0);

	/* Per-ring enable bitmap. */
	uint32_t cfg = genet_read(state, GENET_TDMA_REGS_OFF + GENET_TDMA_RING_CFG);
	cfg |= 1u << GENET_DEFAULT_RING;
	genet_write(state, GENET_TDMA_REGS_OFF + GENET_TDMA_RING_CFG, cfg);

	/* Global TDMA enable + flag this ring as a default queue. The default-queue
	 * select bit is at (RBUF_EN_LSB + ring_idx). */
	uint32_t ctrl = genet_read(state, GENET_TDMA_REGS_OFF + GENET_TDMA_CTRL);
	ctrl |= GENET_TDMA_CTRL_TDMA_EN |
		(1u << (GENET_TDMA_CTRL_RBUF_EN_LSB + GENET_DEFAULT_RING));
	genet_write(state, GENET_TDMA_REGS_OFF + GENET_TDMA_CTRL, ctrl);
}


static void genet_macSetSpeed(genet_state_t *state, int speed, int full_duplex)
{
	uint32_t cmd = genet_read(state, UMAC_CMD);

	cmd &= ~CMD_SPEED_MASK;
	switch (speed) {
		case 10:   cmd |= CMD_SPEED_10; break;
		case 100:  cmd |= CMD_SPEED_100; break;
		case 1000: cmd |= CMD_SPEED_1000; break;
		default:                          break;  /* leave previous setting */
	}

	if (full_duplex) {
		cmd &= ~CMD_HD_EN;
	}
	else {
		cmd |= CMD_HD_EN;
	}

	cmd |= CMD_TX_EN | CMD_RX_EN;

	/* Ignore 802.3x PAUSE flow control (both directions) — matches the VideoCore
	 * firmware's proven-working gigabit UMAC_CMD (dumped 0x1000010b: sets bits 8+28).
	 * Phoenix was leaving these clear (honoring PAUSE). With the newly-added 2.5G
	 * switch, honoring a PAUSE frame that trails our TX can gate the MAC and drop the
	 * reply that follows; the firmware never sees this because it ignores PAUSE. */
	cmd |= CMD_RX_PAUSE_IGNORE | CMD_TX_PAUSE_IGNORE;

	/* PROMISC is set only when we fell back to the locally-administered
	 * MAC. With a real board MAC from VideoCore, the unicast filter is
	 * the correct path — promisc here would just hurt CPU under broadcast
	 * storms. */
	if (state->mac_is_fallback) {
		cmd |= CMD_PROMISC;
	}
	else {
		cmd &= ~CMD_PROMISC;
	}

	genet_write(state, UMAC_CMD, cmd);
}


/* --- RX ring + polling thread (Tier 3) ------------------------- */

static int genet_initRxRing(genet_state_t *state)
{
	uint32_t ring_off = GENET_RX_RINGS_OFF + GENET_DEFAULT_RING * GENET_DMA_RING_SIZE;
	uint32_t bd_off, cons, cfg, ctrl;
	unsigned i;

	/* Allocate the RX buffer pool and program each BD with its address.
	 * The BD addresses are written once and never touched again — the
	 * hardware writes received frames into the same physical buffer
	 * each time the BD cycles past. We just read the status word per
	 * arrival to learn the per-frame length and flags.
	 *
	 * Allocate the whole GENET_RX_POOL_SLOTS-buffer pool in a SINGLE contiguous
	 * dmammap (avoids the per-slot-allocation cliff that once forced 16 aliased
	 * buffers) and carve it. The first GENET_TOTAL_DESC buffers arm the 256 BDs
	 * one-to-one; the remainder seed the zero-copy free list. No BD ever shares
	 * a buffer, so the HW ring's flow control is honoured and no in-flight frame
	 * is overwritten. */
#if GENET_RX_CACHEABLE
	/* Policy B: write-back cacheable pool + per-frame cache maintenance (below). */
	state->rx_pool = dmammap_cached(GENET_RX_POOL_SLOTS * GENET_MAX_FRAME);
#else
	state->rx_pool = dmammap(GENET_RX_POOL_SLOTS * GENET_MAX_FRAME);
#endif
	if (state->rx_pool == NULL) {
		genet_printf(state, "dmammap RX pool (%u KB) failed",
			(GENET_RX_POOL_SLOTS * GENET_MAX_FRAME) / 1024u);
		return -ENOMEM;
	}
	state->rx_pool_phys = va2pa(state->rx_pool);
#if GENET_RX_CACHEABLE
	/* Print the cacheable pool's PA + span so it can be checked against the GPU
	 * scanout high-mem region (e.g. the Pi 4 plo framebuffer triple-buffers around
	 * 0x3d3b2000..0x3eb84000). A cacheable RX pool that overlaps scanout would let
	 * RX DMA + cache maintenance clobber the framebuffer. */
	genet_printf(state, "RXCACHE pool PA=0x%08x..0x%08x (%u KB, cacheable); TX pool PA=0x%08x",
		(unsigned)state->rx_pool_phys,
		(unsigned)(state->rx_pool_phys + GENET_RX_POOL_SLOTS * GENET_MAX_FRAME),
		(GENET_RX_POOL_SLOTS * GENET_MAX_FRAME) / 1024u,
		(unsigned)state->tx_buf_phys);
#endif
	for (i = 0; i < GENET_RX_POOL_SLOTS; ++i) {
		state->rx_bufs[i] = (uint8_t *)state->rx_pool + (size_t)i * GENET_MAX_FRAME;
		state->rx_bufs_phys[i] = state->rx_pool_phys + (addr_t)i * GENET_MAX_FRAME;
		state->rx_pc[i].state = state;
		state->rx_pc[i].idx = (uint16_t)i;
		state->rx_pc[i].pc.custom_free_function = genet_rxbufFree;
	}
	/* Arm the 256 BDs with buffers 0..255; the rest seed the free list. */
	for (i = 0; i < GENET_TOTAL_DESC; ++i) {
		state->rx_bd_buf[i] = (uint16_t)i;
#if GENET_RX_CACHEABLE
		/* dma_sync_for_device: clean+invalidate so no dirty line (the pool is
		 * freshly mapped cacheable and may carry the kernel's zeroing) can write
		 * back over the device's first DMA into this slot. */
		genet_dcacheCleanInvalRx(state->rx_bufs[i], GENET_MAX_FRAME);
#endif
		bd_off = GENET_RX_DESCS_OFF + i * GENET_DMA_DESC_SIZE;
		genet_write(state, bd_off + 4, (uint32_t)(state->rx_bufs_phys[i] & 0xFFFFFFFFu));
		genet_write(state, bd_off + 8, (uint32_t)((uint64_t)state->rx_bufs_phys[i] >> 32));
		genet_write(state, bd_off + 0, 0);
	}
	state->rx_free_top = 0;
	for (i = GENET_TOTAL_DESC; i < GENET_RX_POOL_SLOTS; ++i)
		state->rx_free[state->rx_free_top++] = (uint16_t)i;
	if (mutexCreate(&state->rx_free_lock) != 0) {
		genet_printf(state, "rx_free_lock create failed");
		return -ENOMEM;
	}

	/* Same burst size convention as TDMA. */
	genet_write(state, GENET_RDMA_REGS_OFF + GENET_TDMA_SCB_BURST_SIZE,
		GENET_DMA_DEFAULT_BURST);

	/* END_ADDR spans the FULL 256-BD default-queue area (words 0..767).
	 * BUF_SIZE depth must match. Matches Linux's bcmgenet_init_rx_ring. */
	genet_write(state, ring_off + GENET_RDMA_RING_START_ADDR, 0);
	genet_write(state, ring_off + GENET_RDMA_RING_END_ADDR,
		(GENET_TOTAL_DESC * GENET_DMA_DESC_SIZE / 4u) - 1u);
	genet_write(state, ring_off + GENET_RDMA_RING_READ_PTR, 0);
	genet_write(state, ring_off + GENET_RDMA_RING_WRITE_PTR, 0);

	/* RX indices are MIRRORED from TX: HW writes PROD (at 0x08),
	 * SW writes CONS (at 0x0C). At init, sync our c_index to whatever
	 * HW is at so we don't see stale frames. */
	cons = genet_read(state, ring_off + GENET_RDMA_RING_PROD_INDEX);
	genet_write(state, ring_off + GENET_RDMA_RING_CONS_INDEX, cons);
	state->rx_c_index = cons;
	state->rx_index = cons % GENET_TOTAL_DESC;
	state->rx_pkts_seen = 0;

	genet_write(state, ring_off + GENET_RDMA_RING_BUF_SIZE,
		(GENET_TOTAL_DESC << 16) | (GENET_MAX_FRAME & 0xFFFFu));
	genet_write(state, ring_off + GENET_RDMA_RING_MBUF_DONE, 1);

	/* RX interrupt-coalescing TIMEOUT backstop for the default queue (ring 16).
	 * MBUF_DONE=1 above requests an interrupt per completed buffer, but the ring's
	 * RXDMA_DONE is a single latched bit: genet_irqHandler clears it on entry and
	 * genet_drainRxRing snapshots the producer index once, so a buffer whose
	 * producer update becomes visible in the sub-microsecond window after that
	 * snapshot — seen only at gigabit line rate — is left undelivered with NO
	 * pending interrupt. Its only rescue was the NEXT inbound frame's IRQ, i.e.
	 * the peer's ~200 ms TCP RTO retransmit; at gigabit a lone unicast reply (an
	 * ARP reply or TCP SYN-ACK) can strand this way and stall the whole
	 * connection. This HW timer re-raises the ring RX interrupt within ~57 us
	 * whenever >=1 buffer is undelivered, bounding the stall to microseconds.
	 * Both IRQ-driven upstream drivers (Linux DMA_RING16_TIMEOUT, NetBSD
	 * genet_set_rxthresh) program it; Phoenix previously left it at reset 0
	 * (disabled). The timeout lives in the GLOBAL RDMA control block at 0x6C, NOT
	 * the per-ring block (where 0x2C is READ_PTR). */
	genet_write(state, GENET_RDMA_REGS_OFF + GENET_DMA_RING16_TIMEOUT,
		GENET_DMA_TIMEOUT_TICKS);

	/* XON/XOFF threshold — at 0 the RX engine is always-XOFF. */
	genet_write(state, ring_off + GENET_RDMA_RING_XON_XOFF,
		(GENET_DMA_FC_THRESH_LO << GENET_DMA_XOFF_THRESH_SHIFT) |
		GENET_DMA_FC_THRESH_HI);

	/* RBUF pass-through bits — must be set BEFORE we flip DMA enable.
	 * Linux's init_umac does the RBUF programming up-front and only later
	 * flips the DMA_EN bits in DMA_CTRL.
	 *   - RBUF_CTRL.RBUF_64B_EN  (bit 0): 64B burst path UMAC -> RDMA
	 *   - RBUF_CTRL.RBUF_ALIGN_2B (bit 1): L3 header 4-byte aligned
	 *   - RBUF_CHK_CTRL.RBUF_RXCHK_EN + RBUF_L3_PARSE_DIS: turn on the
	 *     RX checker, skip L3 inspection (we don't offload checksums)
	 *   - RBUF_TBUF_SIZE_CTRL=1 is the v3+ init step
	 */
	uint32_t rbuf = genet_read(state, RBUF_CTRL);
	rbuf |= RBUF_ALIGN_2B;  /* TEST: RBUF_64B_EN OFF to match firmware (rbufctl fw=0xc040) — no 64-byte RX status block; keep the 2-byte align for lwip's ETH_PAD */
	genet_write(state, RBUF_CTRL, rbuf);

	/* TEST: match the VideoCore firmware's proven-working gigabit config, which leaves
	 * RBUF_CHK_CTRL = 0 (RX checksum checker OFF). Phoenix was enabling RBUF_RXCHK_EN +
	 * RBUF_L3_PARSE_DIS (dump: fw rbufchk=0x00 vs phx 0x21). The RX checker sits in the
	 * RBUF front-end — exactly where the missed reply is dropped (MAC-front-end, upstream
	 * of RDMA, no FCS, MIB doesn't count it) — so a checker misbehaving on a frame that
	 * closely trails our TX is a candidate for the gigabit post-TX RX drop. The 64-byte
	 * status prefix (RBUF_64B_EN) is separate and left ON, so RX frame parsing is
	 * unchanged; the checker just no longer inspects/gates the RX stream. */
	genet_write(state, RBUF_CHK_CTRL, 0);

	genet_write(state, RBUF_TBUF_SIZE_CTRL, 1);

	/* Disable MAC-side EEE / energy-saving on the RX path — the MAC-side half of
	 * the PHY AutogrEEEn/LPI RX-drop (a frame arriving while the RX path is powering
	 * back up after an idle gap is lost before it reaches the ring). Linux
	 * force-clears RBUF_ENERGY_CTRL with the note "RBUF EEE/PM can break the RX path
	 * on GENET. Keep it disabled." Also clear UMAC EEE_EN. Pairs with the PHY-side
	 * AutogrEEEn/LPI/EEE disable in ephy.c (= the Pi's dtparam=eee=off). */
	genet_write(state, GENET_RBUF_OFF + 0x9Cu /* RBUF_ENERGY_CTRL */,
		genet_read(state, GENET_RBUF_OFF + 0x9Cu) & ~0x3u /* RBUF_EEE_EN|RBUF_PM_EN */);
	genet_write(state, GENET_UMAC_OFF + 0x064u /* UMAC_EEE_CTRL */,
		genet_read(state, GENET_UMAC_OFF + 0x064u) & ~0x8u /* EEE_EN (bit3) */);

	/* Now the Linux-style two-phase DMA enable:
	 *   1. RDMA_RING_CFG: per-ring enable bitmap (ring 16 only).
	 *   2. DMA_CTRL: ring-default-queue enable bit, NO DMA_EN yet.
	 *   3. DMA_CTRL: |= DMA_EN — flip the global DMA gate last.
	 * Doing it in three steps matches the Linux init order and avoids
	 * an early DMA fetch from an unfinished ring config. */
	cfg = genet_read(state, GENET_RDMA_REGS_OFF + GENET_TDMA_RING_CFG);
	cfg |= 1u << GENET_DEFAULT_RING;
	genet_write(state, GENET_RDMA_REGS_OFF + GENET_TDMA_RING_CFG, cfg);

	ctrl = genet_read(state, GENET_RDMA_REGS_OFF + GENET_TDMA_CTRL);
	ctrl |= 1u << (GENET_TDMA_CTRL_RBUF_EN_LSB + GENET_DEFAULT_RING);
	genet_write(state, GENET_RDMA_REGS_OFF + GENET_TDMA_CTRL, ctrl);

	ctrl |= GENET_TDMA_CTRL_TDMA_EN;
	genet_write(state, GENET_RDMA_REGS_OFF + GENET_TDMA_CTRL, ctrl);

	return 0;
}


/* custom-pbuf free callback: runs on the tcpip thread when lwip drops the last
 * ref. Returns the buffer to the free list (cross-thread vs the drain -> lock). */
static void genet_rxbufFree(struct pbuf *p)
{
	genet_rxbuf_t *rb = (genet_rxbuf_t *)p;   /* pc is first member: &pc.pbuf == p */
	genet_state_t *state = (genet_state_t *)rb->state;

	mutexLock(state->rx_free_lock);
	if (state->rx_free_top < (int)GENET_RX_POOL_SLOTS)
		state->rx_free[state->rx_free_top++] = rb->idx;
	mutexUnlock(state->rx_free_lock);
}


/* Pop a spare buffer index for refilling a BD, or -1 if the free list is dry. */
static int genet_rxbufPop(genet_state_t *state)
{
	int idx = -1;

	mutexLock(state->rx_free_lock);
	if (state->rx_free_top > 0)
		idx = state->rx_free[--state->rx_free_top];
	mutexUnlock(state->rx_free_lock);
	return idx;
}


static void genet_drainRxRing(genet_state_t *state)
{
	uint32_t ring_off = GENET_RX_RINGS_OFF + GENET_DEFAULT_RING * GENET_DMA_RING_SIZE;

	/* RDMA PROD_INDEX is at offset 0x08 (NOT 0x0C, which is the TX
	 * layout — RDMA mirrors the producer/consumer pair). */
	uint32_t prod = genet_read(state,
		ring_off + GENET_RDMA_RING_PROD_INDEX) & 0xFFFFu;

	/* DMA read barrier (Linux dma_rmb()): the RX DMA engine writes the frame
	 * payload into the (uncached Normal-NC) buffer BEFORE it advances PROD_INDEX.
	 * Reading PROD above tells us frames are ready, but without a load-load
	 * barrier the CPU may speculatively read the descriptor status / payload
	 * ahead of the PROD read and observe pre-DMA (stale/partial) bytes — the
	 * frame is delivered up the stack CORRUPT, lwip's checksum rejects it, and
	 * the peer only makes progress on its ~200 ms RTO retransmit. This races
	 * hardest right after a TX (the irq thread is already awake, so the drain
	 * runs at minimum latency), which is exactly when the NFS SYN-ACK / RPC
	 * reply were being dropped at gigabit. Ordering all payload reads after the
	 * PROD observation closes the window. Both BSD genet drivers issue the
	 * equivalent BUS_DMASYNC_POSTREAD here. */
	__asm__ volatile("dmb ld" ::: "memory");

#if GENET_RXSTATS_LOG
	state->drain_wakes++;
#endif
#if (GENET_RX_INPUT_BATCH > 0) && LWIP_TCPIP_CORE_LOCKING_INPUT
	unsigned rx_batched = 0;
	GENET_RX_BURST_LOCK();
#endif
	while (prod != (state->rx_c_index & 0xFFFFu)) {
		uint32_t bd_off = GENET_RX_DESCS_OFF +
			state->rx_index * GENET_DMA_DESC_SIZE;
		uint32_t status = genet_read(state, bd_off + 0);
		uint16_t frame_len_total = (uint16_t)((status & BD_LEN_MASK) >> BD_LEN_SHIFT);

		/* GENET prepends a 66-byte block to every frame (2-byte
		 * alignment + 64-byte status, see RBUF_64B_EN + RBUF_ALIGN_2B
		 * during init). lwip is built with ETH_PAD_SIZE=2, so the pbuf
		 * we hand up must reserve 2 bytes of head pad before the L2
		 * header for ethernet_input's pbuf_remove_header. */
		if (frame_len_total > GENET_RX_STATUS_PREFIX &&
			(status & (BD_STATUS_SOP | BD_STATUS_EOP)) ==
			(BD_STATUS_SOP | BD_STATUS_EOP) &&
			(status & GENET_RX_STATUS_ERROR_MASK) == 0u) {
			uint16_t pay_len = frame_len_total - GENET_RX_STATUS_PREFIX;
			uint16_t bufidx = state->rx_bd_buf[state->rx_index];
			uint8_t *buf = state->rx_bufs[bufidx];
			uint8_t *frame = buf + GENET_RX_STATUS_PREFIX;
			int nb;

#if GENET_RXFRAME_LOG
			/* Discriminating RX diagnostic (gigabit delivered-but-corrupt triage):
			 * for NFS/TCP frames (port 2049) log the header fields AS THE DRIVER
			 * READS THEM FROM THE DMA BUFFER, plus the IP-header checksum computed
			 * over those bytes. The host emits a correct IP header, so iphdrck==0xFFFF
			 * means the bytes in Pi memory are intact (delivered clean -> lwip
			 * rejects for another reason); iphdrck!=0xFFFF proves the frame is CORRUPT
			 * in memory when handed up (stale/aliased/partial-DMA). Only TCP:2049 so
			 * the UART isn't flooded (~a dozen frames per mount attempt). */
			if (pay_len >= 54u) {
				const uint8_t *f = frame;
				uint16_t eth = (uint16_t)((f[12] << 8) | f[13]);
				if (eth == 0x0800u && f[23] == 6u) {
					uint8_t ihl = (uint8_t)((f[14] & 0x0fu) * 4u);
					const uint8_t *tcp = f + 14 + ihl;
					uint16_t sport = (uint16_t)((tcp[0] << 8) | tcp[1]);
					uint16_t dport = (uint16_t)((tcp[2] << 8) | tcp[3]);
					if (sport == 2049u || dport == 2049u) {
						uint32_t s = 0;
						unsigned i;
						uint16_t iplen = (uint16_t)((f[16] << 8) | f[17]);
						for (i = 0; i < ihl; i += 2)
							s += (uint32_t)((f[14 + i] << 8) | f[14 + i + 1]);
						while ((s >> 16) != 0u)
							s = (s & 0xFFFFu) + (s >> 16);
						/* Full TCP checksum over the bytes AS DELIVERED (pseudo-header
						 * src/dst IP + proto 6 + TCP length, then TCP header+payload).
						 * ==0xFFFF => the ENTIRE frame (incl. the TCP tail after the IP
						 * header) is intact in the driver's hands -> corruption is
						 * post-handoff or lwip mis-rejects. !=0xFFFF => the TCP tail is
						 * corrupt in memory (DMA/partial-write) even though the IP header
						 * survived. Discriminates the two remaining hypotheses. */
						{
							uint32_t ts = 0;
							uint16_t tcplen = (uint16_t)(iplen - ihl);
							ts += (uint32_t)((f[26] << 8) | f[27]);
							ts += (uint32_t)((f[28] << 8) | f[29]);
							ts += (uint32_t)((f[30] << 8) | f[31]);
							ts += (uint32_t)((f[32] << 8) | f[33]);
							ts += 6u;
							ts += tcplen;
							for (i = 0; i < tcplen; i += 2) {
								uint16_t hi = tcp[i];
								uint16_t lo = ((i + 1u) < tcplen) ? tcp[i + 1] : 0u;
								ts += (uint32_t)((hi << 8) | lo);
							}
							while ((ts >> 16) != 0u)
								ts = (ts & 0xFFFFu) + (ts >> 16);
							time_t tnow = 0;
							uint32_t mibrx = genet_read(state, GENET_UMAC_OFF + 0x428u);
							gettime(&tnow, NULL);
							/* mib=MAC total-received count AT delivery. If a stranded
							 * SYN-ACK's mib here is ~equal to the value logged at the
							 * preceding SYN TX, the frame JUST arrived (retransmit; the
							 * original never hit the MAC -> PHY/wire loss). If mib jumped
							 * long ago, the original was received but held (MAC/RBUF/DMA). */
							genet_printf(state,
								"RXF t=%llu mib=%u 2049 sp=%u dp=%u flags=0x%02x len=%u iplen=%u iphdrck=0x%04x tcpck=0x%04x",
								(unsigned long long)tnow, mibrx, sport, dport, tcp[13], pay_len, iplen,
								(unsigned)(s & 0xFFFFu), (unsigned)(ts & 0xFFFFu));
						}
					}
				}
			}
#endif

#if GENET_RX_CACHEABLE
			/* dma_sync_for_cpu: clean+invalidate this slot's lines before ANY
			 * read of its contents (zero-copy hand-up OR copy fallback below),
			 * so the CPU sees what the device DMA'd, not a stale cached copy. */
			genet_dcacheCleanInvalRx(buf, GENET_MAX_FRAME);
#endif
			nb = genet_rxbufPop(state);   /* spare buffer to re-arm this BD */

			if (nb >= 0) {
				/* ZERO-COPY: wrap this DMA buffer in its custom pbuf and hand it
				 * up; re-arm the BD with the spare 'nb' so HW keeps receiving. The
				 * 2-byte ETH pad lives in the status prefix ahead of the frame. */
				genet_rxbuf_t *rb = &state->rx_pc[bufidx];
				uint8_t *payload_mem = frame - ETH_PAD_SIZE;
				uint16_t avail = (uint16_t)(GENET_MAX_FRAME -
					(GENET_RX_STATUS_PREFIX - ETH_PAD_SIZE));
				struct pbuf *p = pbuf_alloced_custom(PBUF_RAW,
					(uint16_t)(pay_len + ETH_PAD_SIZE), PBUF_REF,
					&rb->pc, payload_mem, avail);
				if (p != NULL) {
					((uint8_t *)p->payload)[0] = 0;
					((uint8_t *)p->payload)[1] = 0;
					/* Re-arm BD with the spare BEFORE input(): the BD is SW-owned
					 * until we publish CONS_INDEX after the loop, so HW won't touch
					 * it meanwhile; 'buf' now belongs to lwip until rxbufFree(). */
					state->rx_bd_buf[state->rx_index] = (uint16_t)nb;
#if GENET_RX_CACHEABLE
					/* dma_sync_for_device: the spare may carry dirty lines from
					 * its previous life up the stack — clean+invalidate so they
					 * can't write back over the device's next DMA into this slot. */
					genet_dcacheCleanInvalRx(state->rx_bufs[nb], GENET_MAX_FRAME);
#endif
					genet_write(state, bd_off + 4,
						(uint32_t)(state->rx_bufs_phys[nb] & 0xFFFFFFFFu));
					genet_write(state, bd_off + 8,
						(uint32_t)((uint64_t)state->rx_bufs_phys[nb] >> 32));
					genet_write(state, bd_off + 0, 0);
#if GENET_RXSTATS_LOG
					{
						time_t _i0 = 0, _i1 = 0;
						err_t _ir;
						gettime(&_i0, NULL);
						_ir = GENET_RX_INPUT(state->netif, p);
						gettime(&_i1, NULL);
						state->input_us += (unsigned long long)(_i1 - _i0);
						state->input_calls++;
						if (_ir == ERR_OK) {
							state->rx_zerocopy++;
						}
						else {
							pbuf_free(p);
							state->rx_pkts_dropped++;
						}
					}
#else
					if (GENET_RX_INPUT(state->netif, p) == ERR_OK) {
						state->rx_zerocopy++;
					}
					else {
						pbuf_free(p);   /* returns 'bufidx' via rxbufFree */
						state->rx_pkts_dropped++;
					}
#endif
					nb = -2;        /* handled (success or dropped) */
				}
				else {
					/* custom alloc failed: give the spare back, copy instead. */
					mutexLock(state->rx_free_lock);
					if (state->rx_free_top < (int)GENET_RX_POOL_SLOTS)
						state->rx_free[state->rx_free_top++] = (uint16_t)nb;
					mutexUnlock(state->rx_free_lock);
					nb = -1;
				}
			}

			if (nb == -1) {
				/* COPY FALLBACK (free list dry): copy out, BD keeps its buffer. */
				struct pbuf *p = pbuf_alloc(PBUF_RAW,
					(uint16_t)(pay_len + ETH_PAD_SIZE), PBUF_RAM);
				if (p != NULL) {
					((uint8_t *)p->payload)[0] = 0;
					((uint8_t *)p->payload)[1] = 0;
					if (pbuf_take_at(p, frame, pay_len, ETH_PAD_SIZE) == ERR_OK) {
						if (GENET_RX_INPUT(state->netif, p) != ERR_OK) {
							pbuf_free(p);
							state->rx_pkts_dropped++;
						}
					}
					else {
						pbuf_free(p);
						state->rx_pkts_dropped++;
					}
				}
				else {
					state->rx_pkts_dropped++;
				}
				state->rx_copyfallback++;
			}
		}
		else {
			state->rx_pkts_dropped++;
		}
		state->rx_pkts_seen++;

		state->rx_index = (state->rx_index + 1u) % GENET_TOTAL_DESC;
		state->rx_c_index = (state->rx_c_index + 1u) & 0xFFFFu;
#if (GENET_RX_INPUT_BATCH > 0) && LWIP_TCPIP_CORE_LOCKING_INPUT
		/* Bound the core-lock hold: release+reacquire every CHUNK frames so a
		 * large backlog can't starve other core-lock users (app TX, timers). */
		if (++rx_batched >= (unsigned)GENET_RX_INPUT_BATCH) {
			GENET_RX_BURST_UNLOCK();
			rx_batched = 0;
			GENET_RX_BURST_LOCK();
		}
#endif
	}
#if (GENET_RX_INPUT_BATCH > 0) && LWIP_TCPIP_CORE_LOCKING_INPUT
	GENET_RX_BURST_UNLOCK();
#endif

	/* Hand all consumed BDs back to HW in one shot. */
	genet_write(state, ring_off + GENET_RDMA_RING_CONS_INDEX,
		state->rx_c_index);
}


/* INTRL2_0 IRQ handler — runs in interrupt context. Masks the bits it
 * picks up so the line doesn't re-fire before the service thread drains
 * the affected ring, then signals the cond for it to run. */
static int genet_irqHandler(unsigned int n, void *arg)
{
	genet_state_t *state = arg;
	uint32_t stat, mask, pending;

	(void)n;

	stat = genet_read(state, GENET_INTRL2_0_OFF + INTRL2_CPU_STAT);
	mask = genet_read(state, GENET_INTRL2_0_OFF + INTRL2_CPU_MASK_STAT);
	pending = stat & ~mask;
	if (pending == 0u) {
		return 0;
	}

	/* Mask + clear-on-write so the wire doesn't re-assert before
	 * genet_irqThread services it. */
	genet_write(state, GENET_INTRL2_0_OFF + INTRL2_CPU_MASK_SET, pending);
	genet_write(state, GENET_INTRL2_0_OFF + INTRL2_CPU_CLEAR, pending);

	state->irq_events |= pending;
	return 1;
}


static void genet_irqThread(void *arg)
{
	genet_state_t *state = arg;
	uint32_t events;

	mutexLock(state->irq_lock);
	for (;;) {
		while (state->irq_events == 0u) {
			/* Short bounded wait + poll-drain backstop. HW-measured: an RX frame
			 * arriving ~100 us after a TX (e.g. the NFS SYN-ACK right after our SYN,
			 * at gigabit) has its RX_DMA_DONE interrupt lost — the frame is DMA'd into
			 * the ring (PROD advances) but the irq thread is never woken, so it
			 * strands until the NEXT inbound frame re-fires the IRQ ~= the peer's
			 * ~1 s RTO retransmit -> the mount times out. Neither the post-unmask
			 * re-drain nor the HW RX-coalesce timeout (DMA_RING16_TIMEOUT) rescues it.
			 * So on every wait return, unconditionally re-read PROD_INDEX and drain
			 * any frame the missing interrupt stranded. This bounds RX latency to the
			 * poll interval (2 ms) regardless of the interrupt-loss root cause, the
			 * same poll-robustness U-Boot's bcmgenet has by construction. */
			condWait(state->irq_cond, state->irq_lock, GENET_RX_POLL_US);
			if (state->irq_events == 0u) {
				uint32_t rring = GENET_RX_RINGS_OFF +
					GENET_DEFAULT_RING * GENET_DMA_RING_SIZE;
				mutexUnlock(state->irq_lock);
				state->rx_polls++;   /* fork-closer: proves the poll actually runs */
				uint32_t prod_full = genet_read(state, rring + GENET_RDMA_RING_PROD_INDEX);
				if ((prod_full & 0xFFFFu) != (state->rx_c_index & 0xFFFFu)) {
					state->rx_pollrescue++;
					genet_drainRxRing(state);
				}
#if GENET_RXFRAME_LOG
				/* When the ring looks empty but frames should be arriving, dump the
				 * pre-ring state ~1/s: full PROD (top 16b = HW discard counter),
				 * INTRL2 STAT/MASK (is RX_DMA_DONE latched while the ring is empty?),
				 * and RDMA DMA_CTRL (did RX DMA_EN drop?). Distinguishes discard vs
				 * latched-but-not-woken vs DMA-disabled. */
				else if ((state->rx_polls % 500u) == 0u) {
					time_t tnow = 0;
					uint32_t istat = genet_read(state, GENET_INTRL2_0_OFF + INTRL2_CPU_STAT);
					/* Read-and-CLEAR the sticky, masked RX-DMA per-packet/per-buffer
					 * completion bits (14=PDONE, 15=BDONE) so the NEXT dump's istat
					 * shows whether the RX DMA completed anything in the interval
					 * (safe: masked, wakes nothing). */
					genet_write(state, GENET_INTRL2_0_OFF + INTRL2_CPU_CLEAR,
						(1u << 14) | (1u << 15));
					/* MIB HW counters (free-running; deltas): rx total received pkts
					 * (UMAC+0x428) and rx FCS/CRC errors (UMAC+0x438). Proves whether
					 * the frame reached the MAC at all: rx_pkt climbing while PROD
					 * frozen => frame in MAC/RBUF, DMA stall; rx_fcs climbing =>
					 * corrupt at gigabit (RGMII); neither => frame never hit the MAC. */
					uint32_t mib_rxpkt = genet_read(state, GENET_UMAC_OFF + 0x428u);
					uint32_t mib_rxfcs = genet_read(state, GENET_UMAC_OFF + 0x438u);
					gettime(&tnow, NULL);
					genet_printf(state,
						"RXPOLL t=%llu polls=%lu prodfull=0x%08x cidx=%u istat=0x%08x mib_rxpkt=%u mib_rxfcs=%u",
						(unsigned long long)tnow, state->rx_polls, prod_full,
						state->rx_c_index & 0xFFFFu, istat, mib_rxpkt, mib_rxfcs);
				}
#endif
				mutexLock(state->irq_lock);
			}
		}
		events = state->irq_events;
		state->irq_events = 0u;
		mutexUnlock(state->irq_lock);

		if ((events & INTRL2_0_RX_DMA_DONE) != 0u) {
			genet_drainRxRing(state);
		}
		/* TX_DMA_DONE / LINK_UP / LINK_DOWN are not unmasked today.
		 * If they ever fire (spurious), the mask-then-clear in the
		 * handler still leaves them safe to ignore here. */

		/* Re-unmask the bits we just serviced so future events wake us. Unmask
		 * FIRST (before the re-drain below) so a frame arriving after the re-check
		 * re-fires the LIVE interrupt rather than relying on the latch semantics. */
		genet_write(state, GENET_INTRL2_0_OFF + INTRL2_CPU_MASK_CLEAR,
			events);

		/* Level-triggered close for the edge-dependent RX drain (the gigabit
		 * NFS-stall root cause). RX_DMA_DONE is a SINGLE latched bit for the whole
		 * ring; genet_irqHandler CLEARs it on entry and genet_drainRxRing snapshots
		 * RDMA PROD_INDEX only ONCE. A frame that latched the bit but whose
		 * producer-index update was not visible to that snapshot (a sub-us window
		 * under a 1 Gbps micro-burst) is stranded in the ring with NO pending
		 * interrupt -> the thread parks and the frame is drained only when the NEXT
		 * inbound frame re-fires RX_DMA_DONE, ~200 ms later = the peer's RTO
		 * retransmit -> a delayed ACK -> the mount stalls/times out. HW counters
		 * stay clean because nothing is dropped, only drained late; it is
		 * gigabit-only because at 100 Mbps the inter-arrival gap (>=14 us) hides the
		 * window. Now that RX is unmasked, re-read the producer and drain while the
		 * ring is non-empty: a frame past this check re-fires the live IRQ, a frame
		 * before it is caught here -> none can be stranded regardless of
		 * producer/STAT/DMA visibility ordering. Reentrancy-safe: drain runs only
		 * in this thread; worst case is a spurious empty drain. */
		if ((events & INTRL2_0_RX_DMA_DONE) != 0u) {
			uint32_t rring = GENET_RX_RINGS_OFF +
				GENET_DEFAULT_RING * GENET_DMA_RING_SIZE;
			while ((genet_read(state, rring + GENET_RDMA_RING_PROD_INDEX) & 0xFFFFu)
					!= (state->rx_c_index & 0xFFFFu)) {
				state->rx_rearm_stranded++;
				genet_drainRxRing(state);
			}
		}

		mutexLock(state->irq_lock);
	}
}


/* --- Link-state callback ---------------------------------------- */

static void genet_dhcpStartCb(void *arg)
{
	struct netif *netif = arg;
	err_t err;

	netif_set_default(netif);

	/* Kick DHCP via tcpip_callback so it runs in the tcpip-thread context
	 * required by LWIP_TCPIP_CORE_LOCKING. */
	err = dhcp_start(netif);
	genet_printf((genet_state_t *)netif->state,
		"dhcp_start: %d (0=ok); netif waits for OFFER", (int)err);

	/* Gratuitous ARP after dhcp_start is a no-op (netif IP is 0.0.0.0);
	 * lwip handles that gracefully. The first useful ARP fires later
	 * when DHCP completes and netif_set_addr runs from dhcp.c. */
	(void)etharp_gratuitous(netif);
}


static void genet_setLinkState(void *arg, int state_up)
{
	struct netif *netif = arg;
	genet_state_t *state = netif->state;
	int full_duplex = 0;
	int speed;

	if (!state_up) {
		if (state->last_link_up) {
			genet_printf(state, "link down");
		}
		state->last_link_up = 0;
		netif_set_link_down(netif);
		return;
	}

	speed = ephy_linkSpeed(&state->phy, &full_duplex);
	if (state->last_link_up == 0 || speed != state->last_speed ||
		full_duplex != state->last_duplex) {
		genet_printf(state, "link up: %d Mbps %s-duplex",
			speed, full_duplex ? "full" : "half");
		/* Program UMAC_CMD.SPEED/duplex (+ TX_EN|RX_EN) ONLY on an actual link
		 * change — NOT on every 1 s link-poll tick. genet_setLinkState is called
		 * from the 1 Hz link poll; re-writing UMAC_CMD each tick momentarily
		 * re-syncs the MAC and drops a frame that is in-flight across the write
		 * (no FCS error, no HW discard, not produced into the RX ring). At gigabit
		 * that manifests as deterministic loss of the first reply after a request
		 * (NFS SYN-ACK / RPC reply), recovered only on the peer's ~1 s RTO
		 * retransmit -> the mount times out. Gating it on a real change removes the
		 * periodic RX-blackout while still programming the rate on first link-up
		 * and on genuine renegotiation. */
		genet_macSetSpeed(state, speed, full_duplex);
#if GENET_RXFRAME_LOG
		/* Phoenix's post-config MAC state — compare against the "GENETCFG fw:" dump
		 * (firmware's proven-good gigabit config) taken at driver entry. */
		genet_printf(state,
			"GENETCFG phx: oob=0x%08x pwrmgmt=0x%08x portctrl=0x%08x umaccmd=0x%08x gphyctrl=0x%08x rbufctl=0x%08x tbufctl=0x%08x rbufchk=0x%08x",
			genet_read(state, EXT_RGMII_OOB_CTRL), genet_read(state, EXT_EXT_PWR_MGMT),
			genet_read(state, SYS_PORT_CTRL), genet_read(state, UMAC_CMD),
			genet_read(state, EXT_GPHY_CTRL), genet_read(state, RBUF_CTRL),
			genet_read(state, 0x600u /* TBUF_CTRL */), genet_read(state, RBUF_CHK_CTRL));
#endif
	}
	state->last_link_up = 1;
	state->last_speed = speed;
	state->last_duplex = full_duplex;

	netif_set_link_up(netif);

	/* Kick DHCP once on the first link-up. dhcp_start touches lwip's
	 * timer + UDP state, which requires the tcpip-thread context with
	 * LWIP_TCPIP_CORE_LOCKING=1 — calling it from this thread directly
	 * "works" (returns ERR_OK) but the DISCOVER never makes it to the
	 * wire because the dhcp timer never starts. Schedule via
	 * tcpip_callback so lwip runs it in the right context. */
	if (state->dhcp_started == 0) {
		err_t err = tcpip_callback(genet_dhcpStartCb, netif);
		genet_printf(state, "tcpip_callback(dhcp_start): %d", (int)err);
		state->dhcp_started = 1;
	}
}


/* --- Link-state poll thread ------------------------------------- */

/* Per-minute RX-stats console line. Gated OFF by default so it doesn't spam the
 * shared console and interrupt interactive psh (user-reported #31). Debug builds
 * re-enable it with -DGENET_RXSTATS_LOG=1. (The stats counters are always kept;
 * only the console print is gated.) */
#ifndef GENET_RXSTATS_LOG
#define GENET_RXSTATS_LOG 0  /* TEMP: gigabit RX-stranding verify */
#endif

static void genet_linkPollThread(void *arg)
{
	genet_state_t *state = arg;
	int speed, full_duplex;
	unsigned tick = 0;

	for (;;) {
		usleep(1000 * 1000);  /* 1s — matches Linux mii_link_poll cadence */

		full_duplex = 0;
		speed = ephy_linkSpeed(&state->phy, &full_duplex);
		genet_setLinkState(state->netif, (speed > 0) ? 1 : 0);

		/* RXSTATS: zero-copy vs copy-fallback ratio + free-list depth (one line/min).
		 * copyfb>0 or free near 0 means the in-flight pool is too small; dropped>0
		 * means the drain is falling behind. Healthy = all-zerocopy, copyfb/dropped 0.
		 * Gated (GENET_RXSTATS_LOG) so user-mode builds keep the console quiet (#31). */
#if GENET_RXSTATS_LOG
		if ((++tick % 5u) == 0u) {
			/* TEMP diag (gigabit RX-loss triage): rbuf_ovfl = HW RX-FIFO overrun
			 * (RBUF+0x94); prod = HW RDMA producer, cidx = driver consumer — if
			 * prod races ahead of cidx the drain is wedged/behind. dropped =
			 * driver-side drop. All three 0 while packets are still lost ⇒ the
			 * loss is HW-FCS (physical), not ring/drain. */
			uint32_t rbuf_ovfl = genet_read(state, GENET_RBUF_OFF + 0x94u);
			uint32_t prod = genet_read(state, GENET_RX_RINGS_OFF +
				GENET_DEFAULT_RING * GENET_DMA_RING_SIZE +
				GENET_RDMA_RING_PROD_INDEX) & 0xFFFFu;
			/* Read back the RX interrupt-coalescing timeout register so we can
			 * confirm the init write to DMA_RING16_TIMEOUT actually took effect
			 * (expect GENET_DMA_TIMEOUT_TICKS, not the reset 0). */
			uint32_t rxtmo = genet_read(state,
				GENET_RDMA_REGS_OFF + GENET_DMA_RING16_TIMEOUT);
			genet_printf(state, "RXSTATS seen=%lu drop=%lu copyfb=%lu free=%d rbuf_ovfl=%u prod=%u cidx=%u rearm_stranded=%lu pollrescue=%lu polls=%lu rxtmo=%u",
				state->rx_pkts_seen, state->rx_pkts_dropped, state->rx_copyfallback,
				state->rx_free_top, rbuf_ovfl, prod, state->rx_c_index & 0xFFFFu,
				state->rx_rearm_stranded, state->rx_pollrescue, state->rx_polls, rxtmo);
			/* Per-frame drain-cost attribution (see the profiling accumulators). */
			genet_printf(state, "RXPROF wakes=%lu seen=%lu input_us=%llu input_calls=%lu txspin_us=%llu tx_spin_calls=%lu",
				state->drain_wakes, state->rx_pkts_seen, state->input_us, state->input_calls,
				state->txspin_us, state->tx_spin_calls);
		}
#else
		(void)tick;
#endif
	}
}


/* --- linkoutput / media ----------------------------------------- */

#define GENET_TX_TIMEOUT_US 100000u  /* 100 ms — enough for 1518 B at 10 Mbps */


static err_t genet_linkOutput(struct netif *netif, struct pbuf *p)
{
	genet_state_t *state = netif->state;
	uint32_t ring_off = GENET_TX_RINGS_OFF + GENET_DEFAULT_RING * GENET_DMA_RING_SIZE;
	uint32_t bd_off, status;
	time_t now, deadline;
	uint16_t len;

	if (state->last_link_up == 0) {
		return ERR_IF;
	}

	if (p->tot_len > GENET_MAX_FRAME + ETH_PAD_SIZE ||
		p->tot_len <= ETH_PAD_SIZE) {
		return ERR_BUF;
	}

	/* lwip with ETH_PAD_SIZE=2 leaves the 2-byte head pad ON the pbuf
	 * even when handing it to the driver's linkoutput (some lwip
	 * versions strip it via pbuf_remove_header before this call;
	 * 2.1.x as shipped here doesn't). Skip the pad when copying to the
	 * DMA buffer — otherwise the wire frame starts with two bytes of
	 * zero before the real dst MAC and the switch drops it. */
	len = p->tot_len - ETH_PAD_SIZE;

	mutexLock(state->tx_lock);

	/* Linearise the pbuf into the single DMA-coherent slot, starting
	 * past the ETH_PAD_SIZE head pad. dmammap memory is uncached, so
	 * no further cache maintenance is needed. */
	pbuf_copy_partial(p, state->tx_buf, len, ETH_PAD_SIZE);

#if GENET_RXFRAME_LOG
	/* TEMP: log NFS/TCP frames lwip asks us to TRANSMIT, to correlate with the
	 * RXF log + host pcap. If lwip generates the handshake ACK after a valid
	 * SYN-ACK is delivered, it appears here; if it does not, the gap is in lwip's
	 * TCP processing, not the driver's TX. */
	if (len >= 54u) {
		const uint8_t *f = state->tx_buf;
		if (((f[12] << 8) | f[13]) == 0x0800 && f[23] == 6u) {
			uint8_t ihl = (uint8_t)((f[14] & 0x0fu) * 4u);
			const uint8_t *tcp = f + 14 + ihl;
			uint16_t sp = (uint16_t)((tcp[0] << 8) | tcp[1]);
			uint16_t dp = (uint16_t)((tcp[2] << 8) | tcp[3]);
			if (sp == 2049u || dp == 2049u) {
				time_t tnow = 0;
				gettime(&tnow, NULL);
				genet_printf(state, "TXF t=%llu mib=%u 2049 sp=%u dp=%u flags=0x%02x len=%u seq=%u ack=%u",
					(unsigned long long)tnow, genet_read(state, GENET_UMAC_OFF + 0x428u), sp, dp, tcp[13], len,
					(unsigned)((tcp[4] << 24) | (tcp[5] << 16) | (tcp[6] << 8) | tcp[7]),
					(unsigned)((tcp[8] << 24) | (tcp[9] << 16) | (tcp[10] << 8) | tcp[11]));
			}
		}
	}
#endif

	/* Program BD[tx_index]: addr-lo, addr-hi, length+status. */
	bd_off = GENET_TX_DESCS_OFF + state->tx_index * GENET_DMA_DESC_SIZE;
	genet_write(state, bd_off + 4, (uint32_t)(state->tx_buf_phys & 0xFFFFFFFFu));
	genet_write(state, bd_off + 8, (uint32_t)((uint64_t)state->tx_buf_phys >> 32));

	/* Length+flags only. Neither Linux nor U-Boot's bcmgenet_xmit sets the
	 * DMA_OWN bit on TX; the producer-index write below is what hands the
	 * descriptor to hardware. Setting OWN here previously kept TDMA from
	 * actually pushing the frame onto the wire (the descriptor was consumed
	 * via cons_index but the MAC never transmitted it). */
	status = ((uint32_t)len << BD_LEN_SHIFT) |
		BD_STATUS_SOP | BD_STATUS_EOP | BD_STATUS_TX_CRC;
	genet_write(state, bd_off + 0, status);

	/* Advance the ring tail. The 16-bit prod_index wraps at 0x10000; the
	 * BD index wraps at TOTAL_DESC. */
	state->tx_index = (state->tx_index + 1u) % GENET_TOTAL_DESC;
	state->tx_prod_index = (state->tx_prod_index + 1u) & 0xFFFFu;
	/* Fence the TX descriptor + Normal-NC payload writes so they are globally
	 * visible before the Device-MMIO producer-index doorbell below — genet_write
	 * is a bare volatile store with no implicit barrier (B7b). Netboot NFS is
	 * empirically reliable (Normal-NC ordering is looser-but-adequate on this SoC),
	 * so this is a defensive correctness fence, not a bug fix. */
	__asm__ volatile("dsb sy" ::: "memory");
	genet_write(state, ring_off + GENET_TDMA_RING_PROD_INDEX, state->tx_prod_index);

	/* Polled completion. TX is single-slot synchronous: at most one
	 * frame is in flight, so latency from condWait/IRQ would dominate
	 * over the few microseconds it takes the MAC to drain a 1518B
	 * frame at 1 Gbps (~12 us). When MQ TX lands this will move to
	 * an IRQ + free-queue ring. */
	gettime(&now, NULL);
	deadline = now + GENET_TX_TIMEOUT_US;
#if GENET_RXSTATS_LOG
	time_t _tx0 = now;
#endif

	for (;;) {
		uint32_t cons = genet_read(state, ring_off + GENET_TDMA_RING_CONS_INDEX);
		if ((cons & 0xFFFFu) == state->tx_prod_index) {
			break;
		}
		gettime(&now, NULL);
		if (now >= deadline) {
			state->tx_timeouts++;
			mutexUnlock(state->tx_lock);
			genet_printf(state, "TX timeout (prod=%u cons=%u)",
				state->tx_prod_index, cons & 0xFFFFu);
			return ERR_TIMEOUT;
		}
	}
#if GENET_RXSTATS_LOG
	gettime(&now, NULL);
	state->txspin_us += (unsigned long long)(now - _tx0);
	state->tx_spin_calls++;
#endif

	state->tx_pkts++;
	mutexUnlock(state->tx_lock);
	return ERR_OK;
}


static const char *genet_media(struct netif *netif)
{
	genet_state_t *state = netif->state;
	int full_duplex = 0;
	int speed = ephy_linkSpeed(&state->phy, &full_duplex);

	switch (speed) {
		case 10:   return full_duplex ? "10Mbps/full-duplex"   : "10Mbps/half-duplex";
		case 100:  return full_duplex ? "100Mbps/full-duplex"  : "100Mbps/half-duplex";
		case 1000: return full_duplex ? "1000Mbps/full-duplex" : "1000Mbps/half-duplex";
		default:   return "unspecified";
	}
}


static int genet_stats(struct netif *netif, char *buf, size_t cap)
{
	genet_state_t *state = netif->state;
	int r;

	r = snprintf(buf, cap,
		"rx=%lu rx_drop=%lu tx=%lu tx_timeout=%lu link=%d/%dMbps/%s mac_src=%s",
		state->rx_pkts_seen, state->rx_pkts_dropped,
		state->tx_pkts, state->tx_timeouts,
		state->last_link_up, state->last_speed,
		state->last_duplex ? "full" : "half",
		state->mac_is_fallback ? "fallback" : "mailbox");

	return (r > 0 && (size_t)r < cap) ? r : 0;
}


/* --- netif init -------------------------------------------------- */

static int genet_parseCfg(genet_state_t *state, char *cfg, char **phy_cfg_out)
{
	char *p;

	if (cfg == NULL) {
		return -EINVAL;
	}

	/* phys */
	state->dev_phys_addr = strtoul(cfg, &p, 0);
	if (*cfg == '\0' || *p++ != ':') {
		return -EINVAL;
	}

	/* irq_general */
	cfg = p;
	state->irq_general = (int)strtoul(cfg, &p, 0);
	if (*cfg == '\0' || *p++ != ':') {
		return -EINVAL;
	}

	/* irq_ring */
	cfg = p;
	state->irq_ring = (int)strtoul(cfg, &p, 0);
	if (*cfg == '\0' || (*p != '\0' && *p++ != ':')) {
		return -EINVAL;
	}

	/* expect "PHY:..." trailing for ephy_init */
	if (strncmp(p, "PHY:", 4) != 0) {
		return -EINVAL;
	}
	*phy_cfg_out = p + 4;
	return 0;
}


static int genet_netifInit(struct netif *netif, char *cfg)
{
	genet_state_t *state = netif->state;
	char *phy_cfg = NULL;
	int err;

	netif->linkoutput = genet_linkOutput;
	state->netif = netif;

	err = genet_parseCfg(state, cfg, &phy_cfg);
	if (err < 0) {
		printf("lwip: genet: bad cfg \"%s\"\n", cfg);
		return err;
	}

	state->mmio = physmmap(state->dev_phys_addr, GENET_MMIO_SIZE);
	if (state->mmio == MAP_FAILED) {
		printf("lwip: genet: physmmap(%08x, %u) failed\n",
			(unsigned)state->dev_phys_addr, GENET_MMIO_SIZE);
		return -ENOMEM;
	}

	err = genet_validateRevision(state);
	if (err < 0) {
		return err;
	}

#if GENET_RXFRAME_LOG
	/* Dump the VideoCore firmware's WORKING gigabit config BEFORE we reset/reconfigure
	 * anything — it just finished a gigabit TFTP session, so these MAC registers are a
	 * proven-good reference on the same silicon. Compared against Phoenix's post-config
	 * dump (after link-up), any divergence is a candidate for the post-TX RX-drop. */
	genet_printf(state,
		"GENETCFG fw: oob=0x%08x pwrmgmt=0x%08x portctrl=0x%08x umaccmd=0x%08x gphyctrl=0x%08x rbufctl=0x%08x tbufctl=0x%08x rbufchk=0x%08x",
		genet_read(state, EXT_RGMII_OOB_CTRL), genet_read(state, EXT_EXT_PWR_MGMT),
		genet_read(state, SYS_PORT_CTRL), genet_read(state, UMAC_CMD),
		genet_read(state, EXT_GPHY_CTRL), genet_read(state, RBUF_CTRL),
		genet_read(state, 0x600u /* TBUF_CTRL */), genet_read(state, RBUF_CHK_CTRL));
#endif

	/* MAC source priority on Pi 4:
	 *   1. UMAC_MAC0/MAC1 (if firmware pre-programmed it — Pi 3 does
	 *      this, Pi 4 does not).
	 *   2. VideoCore mailbox property GET_BOARD_MAC (tag 0x10003).
	 *      This is what Linux's bcmgenet ends up using on Pi 4.
	 *   3. Locally-administered fallback. Lets the netif come up far
	 *      enough to surface other issues; we set CMD_PROMISC in this
	 *      case since the unicast filter would otherwise drop traffic
	 *      destined for the real board MAC. */
	state->mac_is_fallback = false;
	genet_readMac(state);
	if ((state->mac[0] | state->mac[1] | state->mac[2] | state->mac[3] |
		state->mac[4] | state->mac[5]) == 0) {
		uint8_t mbox_mac[6];
		if (genet_mboxGetMac(mbox_mac) == 0 &&
			(mbox_mac[0] | mbox_mac[1] | mbox_mac[2] |
				mbox_mac[3] | mbox_mac[4] | mbox_mac[5]) != 0) {
			memcpy(state->mac, mbox_mac, 6);
			genet_printf(state, "MAC from VideoCore mailbox");
		}
		else {
			state->mac[0] = 0x02;  /* locally administered, unicast */
			state->mac[1] = 0xB8;
			state->mac[2] = 0x27;  /* RPi-Foundation OUI tail, helps log scans */
			state->mac[3] = 0xEB;
			state->mac[4] = 0x00;
			state->mac[5] = 0x01;
			state->mac_is_fallback = true;
			genet_printf(state, "no firmware/mailbox MAC; using LAA fallback (PROMISC on)");
		}
	}
	genet_printf(state, "MAC %02x:%02x:%02x:%02x:%02x:%02x",
		state->mac[0], state->mac[1], state->mac[2],
		state->mac[3], state->mac[4], state->mac[5]);

	/* Quiesce any leftover DMA from the bootloader BEFORE the UMAC reset.
	 * Linux's bcmgenet_open does this in init_dma -> bcmgenet_{rdma,tdma}
	 * _disable; the bootloader's "GENET STOP: 0" message before kernel
	 * handoff doesn't run the same handshake. */
	genet_dmaDisable(state);

	err = genet_resetUmac(state);
	if (err < 0) {
		return err;
	}

	/* Restore MAC after reset. */
	genet_writeMac(state);

	/* UMAC needs to know the largest frame it'll accept. Without this the
	 * RX path drops every packet silently (the reset clears the field to 0).
	 * 1536 = ENET_MAX_MTU_SIZE in Linux: covers 1500-byte payloads + Ethernet
	 * header + VLAN tag + FCS with margin. */
	genet_write(state, UMAC_MAX_FRAME_LEN, 1536);

	/* Copy MAC into netif so lwIP can use it. */
	memcpy(netif->hwaddr, state->mac, 6);
	netif->hwaddr_len = 6;
	netif->mtu = 1500;
	netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

#if !GENET_PHY_ADOPT_FW
	/* GENET_PHY_ADOPT_FW: skip the PHY hard-reset (and, in ephy.c, the soft reset +
	 * autoneg-restart) to ADOPT the VideoCore firmware's already-trained gigabit PHY.
	 * 1000BASE-T echo-cancellation/DSP training state is NOT register-visible; a wrong
	 * post-reset training blinds the PHY to RX during/after its own TX (the exact
	 * post-TX, no-FCS, gigabit-only drop). Adopting the firmware's trained PHY tests
	 * that wholesale. genet_configRgmii is MAC-side and always runs. */
	genet_phyHardReset(state);
#endif
	genet_configRgmii(state);

	state->mdio_bus = register_mdio_bus(&genet_mdio_ops, state);
	if (state->mdio_bus < 0) {
		genet_printf(state, "register_mdio_bus failed: %d", state->mdio_bus);
		return state->mdio_bus;
	}
	genet_printf(state, "MDIO bus %d", state->mdio_bus);

	err = ephy_init(&state->phy, phy_cfg, 0,
		genet_setLinkState, (void *)netif);
	if (err < 0) {
		genet_printf(state, "ephy_init failed: %d", err);
		return err;
	}

	/* Tier 2: single-slot TX buffer + ring init. dmammap returns a
	 * page-aligned uncached MAP_CONTIGUOUS region — exactly what GENET
	 * DMA needs (no D-cache management, low-32-bit physical address). */
	state->tx_buf = dmammap(GENET_MAX_FRAME);
	if (state->tx_buf == NULL) {
		genet_printf(state, "dmammap(%u) for TX failed", GENET_MAX_FRAME);
		return -ENOMEM;
	}
	state->tx_buf_phys = va2pa(state->tx_buf);

	if (mutexCreate(&state->tx_lock) != 0) {
		genet_printf(state, "tx_lock mutexCreate failed");
		return -ENOMEM;
	}

	genet_initTxRing(state);
	genet_printf(state, "TX ring 16 ready (BD %u..%u, buf %p phys=0x%08x)",
		0u, GENET_TOTAL_DESC - 1u, state->tx_buf, (unsigned)state->tx_buf_phys);

	/* RX pool + ring. */
	err = genet_initRxRing(state);
	if (err < 0) {
		return err;
	}
	genet_printf(state, "RX ring ready (%u unique buffers, BD 0..%u)",
		GENET_RX_SLOTS, GENET_RX_SLOTS - 1u);

	/* IRQ plumbing: mask everything in INTRL2_0/1 before registering
	 * the handler (Linux's init_intrl2_set_mask), then enable just
	 * RX_DMA_DONE. */
	genet_write(state, GENET_INTRL2_0_OFF + INTRL2_CPU_MASK_SET, 0xFFFFFFFFu);
	genet_write(state, GENET_INTRL2_0_OFF + INTRL2_CPU_CLEAR, 0xFFFFFFFFu);
	genet_write(state, GENET_INTRL2_1_OFF + INTRL2_CPU_MASK_SET, 0xFFFFFFFFu);
	genet_write(state, GENET_INTRL2_1_OFF + INTRL2_CPU_CLEAR, 0xFFFFFFFFu);

	if (mutexCreate(&state->irq_lock) != 0) {
		genet_printf(state, "irq_lock create failed");
		return -ENOMEM;
	}
	if (condCreate(&state->irq_cond) != 0) {
		genet_printf(state, "irq_cond create failed");
		return -ENOMEM;
	}

	err = interrupt(state->irq_general, genet_irqHandler, state,
		state->irq_cond, &state->irq_handle);
	if (err < 0) {
		genet_printf(state, "interrupt() register IRQ %d: %s (%d)",
			state->irq_general, strerror(-err), err);
		return err;
	}
	genet_printf(state, "IRQ %d registered (INTRL2_0)", state->irq_general);

	err = beginthread(genet_irqThread, 4, state->irq_stack,
		sizeof(state->irq_stack), state);
	if (err != 0) {
		genet_printf(state, "irq thread failed: %d", err);
		return err;
	}

	/* Now unmask RX_DMA_DONE so the service thread starts taking work. */
	genet_write(state, GENET_INTRL2_0_OFF + INTRL2_CPU_MASK_CLEAR,
		INTRL2_0_RX_DMA_DONE);

	/* ephy_init queries the PHY once. With irq:MAC there's no IRQ thread,
	 * so we spin up our own 1 Hz poller that calls back into genet_setLinkState
	 * whenever the link transitions. */
	err = beginthread(genet_linkPollThread, 4, state->link_poll_stack,
		sizeof(state->link_poll_stack), state);
	if (err != 0) {
		genet_printf(state, "link poll thread failed: %d", err);
		return err;
	}

	return 0;
}


/* --- driver registration ---------------------------------------- */

static netif_driver_t genet_drv = {
	.init = genet_netifInit,
	.state_sz = sizeof(genet_state_t),
	.state_align = _Alignof(genet_state_t),
	.name = "genet",
	.media = genet_media,
	.stats = genet_stats,
};


__constructor__(1000) void register_driver_genet(void)
{
	register_netif_driver(&genet_drv);
}
