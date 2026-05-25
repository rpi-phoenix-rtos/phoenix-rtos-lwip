/*
 * Phoenix-RTOS --- LwIP port
 *
 * BCM2711 GENET v5 Ethernet driver (Pi 4, BCM54213PE PHY over RGMII)
 *
 * Copyright 2026 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Scope as of the head of agent/rpi4-genet:
 *   - MMIO map, GENET v5 silicon ID validation, UMAC reset
 *   - MDIO bus exposed to ephy.c (BCM54213PE)
 *   - RGMII / SYS_PORT_CTRL / RBUF / DMA init per Linux + Circle refs
 *   - TX: single-slot polled descriptor (verified on the wire via
 *     host-side tcpdump)
 *   - RX: 256-BD ring with per-BD pre-programmed phys address, 100 Hz
 *     poll thread. HW writes to BD memory observed but RDMA_PROD_INDEX
 *     advancement is still open — TODO(TD-Eth-RX). Diagnostic prints
 *     in genet_rxPollThread are kept until that's resolved.
 *
 * No IRQ wiring yet (Tier 4+). DHCP / ARP / lwIP-level integration is
 * Tier 4 once RX is unblocked. WiFi (BCM43455) is parked behind that.
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

#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"

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
 * RX ring depth. 16 BDs is enough for Tier 3 (one packet, polled) and
 * keeps the init's 16-call dmammap loop well under Phoenix's allocator
 * cliff — bumping to GENET_TOTAL_DESC (256) made the 256 successive
 * MAP_CONTIGUOUS allocations stall lwip startup so it never produced
 * its first print. The ring's BUF_SIZE and END_ADDR are programmed
 * for this count, so the HW only sees the slots we actually filled.
 */
#define GENET_RX_SLOTS    16u




typedef struct {
	addr_t dev_phys_addr;
	volatile uint32_t *mmio;
	struct netif *netif;

	uint8_t mac[6];

	int mdio_bus;
	eth_phy_state_t phy;

	int irq_general;  /* SPI 189 — reserved for Tier 4+ */
	int irq_ring;     /* SPI 190 — reserved for Tier 5 */

	int last_link_up;
	int last_speed;
	int last_duplex;
	uint32_t link_poll_stack[1024] __attribute__((aligned(16)));

	/* TX (Tier 2): single DMA buffer, ring of 256 BDs in MMIO. */
	void *tx_buf;
	addr_t tx_buf_phys;
	handle_t tx_lock;
	uint32_t tx_index;       /* 0..GENET_TOTAL_DESC-1 — BD index in MMIO */
	uint32_t tx_prod_index;  /* 16-bit running counter the HW compares to CONS_INDEX */

	/* RX (Tier 3): per-slot buffers + polling thread. The BD's address
	 * is programmed once at init — HW writes received frames into the
	 * same physical buffer each time the BD comes back around. */
	void *rx_bufs[GENET_RX_SLOTS];
	addr_t rx_bufs_phys[GENET_RX_SLOTS];
	uint32_t rx_index;       /* 0..GENET_TOTAL_DESC-1 — BD index in MMIO */
	uint32_t rx_c_index;     /* SW's view, mirrors RDMA_RING_CONS_INDEX */
	unsigned long rx_pkts_seen;
	unsigned long rx_pkts_dropped;
	uint32_t rx_poll_stack[2048] __attribute__((aligned(16)));
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

	/* UMAC_MAC0 holds bytes [5..2], UMAC_MAC1 holds bytes [1..0] in the
	 * low half-word — matches the Linux bcmgenet layout. */
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

static void genet_phyHardReset(genet_state_t *state)
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

	/* Pi 4 DT sets phy-mode = "rgmii-rxid": internal RX delay enabled
	 * (clear ID_MODE_DIS), TX delay from PCB traces.
	 *
	 * OOB_DISABLE must be SET: that tells the MAC to take link state
	 * from RGMII_LINK (which we write below) instead of the out-of-band
	 * pins from the PHY. Without this bit the MAC silently treats the
	 * link as down and drops every received frame even though TX
	 * (which only needs RGMII_MODE_EN) still works. This was the cause
	 * of the Tier 3 RDMA_PROD_INDEX-stuck-at-0 symptom; matches Linux's
	 * bcmgenet_setup_rgmii / Circle's mii_config exactly. */
	uint32_t v = genet_read(state, EXT_RGMII_OOB_CTRL);

	v |= RGMII_LINK | RGMII_MODE_EN | OOB_DISABLE;
	v &= ~ID_MODE_DIS;

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

	/* TODO(TD-Eth-Promisc): drop once Tier 4 uses the real MAC and
	 * proves the unicast filter doesn't drop ARP replies. PROMISC keeps
	 * the diagnostic surface minimal while we validate Tier 3 RX. */
	cmd |= CMD_PROMISC;

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
	 * We populate the first GENET_RX_SLOTS BDs with unique dmammap'd
	 * buffers, then alias the remaining BDs [GENET_RX_SLOTS .. GENET_TOTAL_DESC-1]
	 * cyclically back to the same buffers. The previous attempt had
	 * END_ADDR set for only 16 BDs, which seems to have made BCM2711
	 * GENET treat BD[0] as also the LAST BD in the ring (WRAP set on
	 * the first received frame). Programming all 256 BD slots with
	 * (aliased) valid addresses + writing the full default-queue
	 * END_ADDR = 767 keeps HW from setting WRAP early. */
	for (i = 0; i < GENET_RX_SLOTS; ++i) {
		state->rx_bufs[i] = dmammap(GENET_MAX_FRAME);
		if (state->rx_bufs[i] == NULL) {
			genet_printf(state, "dmammap RX slot %u failed", i);
			return -ENOMEM;
		}
		state->rx_bufs_phys[i] = va2pa(state->rx_bufs[i]);

		bd_off = GENET_RX_DESCS_OFF + i * GENET_DMA_DESC_SIZE;
		genet_write(state, bd_off + 4, (uint32_t)(state->rx_bufs_phys[i] & 0xFFFFFFFFu));
		genet_write(state, bd_off + 8, (uint32_t)((uint64_t)state->rx_bufs_phys[i] >> 32));
		genet_write(state, bd_off + 0, 0);
	}
	for (i = GENET_RX_SLOTS; i < GENET_TOTAL_DESC; ++i) {
		addr_t pa = state->rx_bufs_phys[i % GENET_RX_SLOTS];
		bd_off = GENET_RX_DESCS_OFF + i * GENET_DMA_DESC_SIZE;
		genet_write(state, bd_off + 4, (uint32_t)(pa & 0xFFFFFFFFu));
		genet_write(state, bd_off + 8, (uint32_t)((uint64_t)pa >> 32));
		genet_write(state, bd_off + 0, 0);
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
	rbuf |= RBUF_ALIGN_2B | RBUF_64B_EN;
	genet_write(state, RBUF_CTRL, rbuf);

	uint32_t chk = genet_read(state, RBUF_CHK_CTRL);
	chk |= RBUF_RXCHK_EN | RBUF_L3_PARSE_DIS;
	genet_write(state, RBUF_CHK_CTRL, chk);

	genet_write(state, RBUF_TBUF_SIZE_CTRL, 1);

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


static void genet_rxPollThread(void *arg)
{
	genet_state_t *state = arg;
	uint32_t ring_off = GENET_RX_RINGS_OFF + GENET_DEFAULT_RING * GENET_DMA_RING_SIZE;
	unsigned ticks = 0;
	uint32_t last_bd0_status = ~0u;

	for (;;) {
		usleep(10 * 1000);  /* 10 ms — Tier 3 polled cadence. */

		/* RDMA PROD_INDEX is at offset 0x08 (NOT 0x0C, which is the
		 * TX layout — RDMA mirrors the producer/consumer pair). */
		uint32_t prod = genet_read(state,
			ring_off + GENET_RDMA_RING_PROD_INDEX) & 0xFFFFu;

		while (prod != (state->rx_c_index & 0xFFFFu)) {
			uint32_t bd_off = GENET_RX_DESCS_OFF +
				state->rx_index * GENET_DMA_DESC_SIZE;
			uint32_t status = genet_read(state, bd_off + 0);
			uint16_t frame_len_total = (uint16_t)((status & BD_LEN_MASK) >> BD_LEN_SHIFT);

			/* GENET prepends a 64-byte RX status block to every frame
			 * (RBUF_64B_EN set during init). The actual Ethernet frame
			 * starts at buf+64 and has length status-encoded - 64. */
			if (frame_len_total > GENET_RX_STATUS_PREFIX &&
				(status & (BD_STATUS_SOP | BD_STATUS_EOP)) ==
				(BD_STATUS_SOP | BD_STATUS_EOP) &&
				(status & GENET_RX_STATUS_ERROR_MASK) == 0u) {
				uint16_t pay_len = frame_len_total - GENET_RX_STATUS_PREFIX;
				uint8_t *buf = state->rx_bufs[state->rx_index % GENET_RX_SLOTS];
				uint8_t *frame = buf + GENET_RX_STATUS_PREFIX;

				struct pbuf *p = pbuf_alloc(PBUF_RAW, pay_len, PBUF_POOL);
				if (p != NULL) {
					if (pbuf_take(p, frame, pay_len) == ERR_OK) {
						if (state->netif->input(p, state->netif) != ERR_OK) {
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
			}
			else {
				/* Malformed BD (no SOP|EOP, error bits, or undersized
				 * frame): drop silently, just advance. */
				state->rx_pkts_dropped++;
			}
			state->rx_pkts_seen++;

			state->rx_index = (state->rx_index + 1u) % GENET_TOTAL_DESC;
			state->rx_c_index = (state->rx_c_index + 1u) & 0xFFFFu;
		}

		/* Hand all consumed BDs back to HW in one shot. */
		genet_write(state, ring_off + GENET_RDMA_RING_CONS_INDEX,
			state->rx_c_index);

		(void)last_bd0_status;
		(void)ticks;
	}
}


/* --- Link-state callback ---------------------------------------- */


/* --- Link-state callback ---------------------------------------- */

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
	}
	state->last_link_up = 1;
	state->last_speed = speed;
	state->last_duplex = full_duplex;

	/* Program UMAC_CMD.SPEED + TX_EN now that the negotiated rate is known.
	 * RX_EN lands in Tier 3 once the RDMA ring is set up. */
	genet_macSetSpeed(state, speed, full_duplex);

	netif_set_link_up(netif);
}


/* --- Link-state poll thread ------------------------------------- */

static void genet_linkPollThread(void *arg)
{
	genet_state_t *state = arg;
	int speed, full_duplex;

	for (;;) {
		usleep(1000 * 1000);  /* 1s — matches Linux mii_link_poll cadence */

		full_duplex = 0;
		speed = ephy_linkSpeed(&state->phy, &full_duplex);
		genet_setLinkState(state->netif, (speed > 0) ? 1 : 0);
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

	if (p->tot_len > GENET_MAX_FRAME) {
		return ERR_BUF;
	}

	len = p->tot_len;

	mutexLock(state->tx_lock);

	/* Linearise the pbuf into the single DMA-coherent slot. dmammap memory
	 * is uncached, so no further cache maintenance is needed. */
	pbuf_copy_partial(p, state->tx_buf, len, 0);

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
	genet_write(state, ring_off + GENET_TDMA_RING_PROD_INDEX, state->tx_prod_index);

	/* Polled completion — Tier 2 doesn't run IRQs yet. */
	gettime(&now, NULL);
	deadline = now + GENET_TX_TIMEOUT_US;

	for (;;) {
		uint32_t cons = genet_read(state, ring_off + GENET_TDMA_RING_CONS_INDEX);
		if ((cons & 0xFFFFu) == state->tx_prod_index) {
			break;
		}
		gettime(&now, NULL);
		if (now >= deadline) {
			mutexUnlock(state->tx_lock);
			genet_printf(state, "TX timeout (prod=%u cons=%u)",
				state->tx_prod_index, cons & 0xFFFFu);
			return ERR_TIMEOUT;
		}
	}

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

	/* Try the firmware-pre-programmed MAC first. On Pi 4 the VideoCore
	 * firmware does *not* push the board MAC into UMAC_MAC0/UMAC_MAC1 —
	 * Linux fetches it from the DT's local-mac-address property or via
	 * the BCM2835 mailbox GET_BOARD_MAC (tag 0x10003) and then writes it
	 * back. Phoenix does not yet expose either route from userspace, so
	 * for Tier 1 we fall back to a deterministic locally-administered
	 * MAC derived from the SoC's GENET MMIO offset. This is enough for
	 * link-up validation; Tier 2+ will plumb a proper MAC source.
	 *   TODO(TD-Eth-MAC): query VideoCore mailbox / DT for the real MAC. */
	genet_readMac(state);
	if ((state->mac[0] | state->mac[1] | state->mac[2] | state->mac[3] |
		state->mac[4] | state->mac[5]) == 0) {
		state->mac[0] = 0x02;  /* locally administered, unicast */
		state->mac[1] = 0xB8;
		state->mac[2] = 0x27;  /* RPi-Foundation OUI tail, helps log scans */
		state->mac[3] = 0xEB;
		state->mac[4] = 0x00;
		state->mac[5] = 0x01;
		genet_printf(state, "no firmware MAC in UMAC_MAC{0,1}; using fallback");
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

	genet_phyHardReset(state);
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

	/* Tier 3: RX pool + ring + polling thread. */
	err = genet_initRxRing(state);
	if (err < 0) {
		return err;
	}
	genet_printf(state, "RX ring 16 ready (%u slots, BD 0..%u)",
		GENET_RX_SLOTS, GENET_RX_SLOTS - 1u);

	err = beginthread(genet_rxPollThread, 4, state->rx_poll_stack,
		sizeof(state->rx_poll_stack), state);
	if (err != 0) {
		genet_printf(state, "rx poll thread failed: %d", err);
		return err;
	}

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
};


__constructor__(1000) void register_driver_genet(void)
{
	register_netif_driver(&genet_drv);
}
