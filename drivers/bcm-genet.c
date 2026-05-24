/*
 * Phoenix-RTOS --- LwIP port
 *
 * BCM2711 GENET v5 Ethernet driver (Pi 4, BCM54213PE PHY over RGMII)
 *
 * Copyright 2026 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Tier 1 scope: link-up only — map MMIO, validate revision, read
 * pre-programmed MAC, reset UMAC, MDIO bus, RGMII config, drive
 * autoneg via ephy.c, report link state.
 *
 * No DMA, no IRQ — the linkoutput callback returns ERR_IF so lwIP
 * sees the netif as "device present but interface down". Tier 2
 * fills in TX, Tier 3 RX, Tier 4 IRQs + DHCP.
 *
 * References (BEHAVIORAL only — fresh-code per CLAUDE.md
 * upstreamability guidance):
 *   - docs/research/ethernet-genet.md (Linux GENET)
 *   - docs/research/ethernet-genet-non-linux.md (FreeBSD if_genet,
 *     Circle bcm54213, U-Boot bcmgenet)
 *   - docs/notes/2026-05-24-eth-tier0-scout.md (Phoenix integration)
 */
#include "netif-driver.h"
#include "physmmap.h"
#include "ephy.h"
#include "bcm-genet-regs.h"

#include "lwip/etharp.h"
#include "lwip/netif.h"

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


typedef struct {
	addr_t dev_phys_addr;
	volatile uint32_t *mmio;
	struct netif *netif;

	uint8_t mac[6];

	int mdio_bus;
	eth_phy_state_t phy;

	int irq_general;  /* SPI 189 — reserved for Tier 4+ */
	int irq_ring;     /* SPI 190 — reserved for Tier 5 */
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
	/* Pi 4 DT sets phy-mode = "rgmii-rxid" — RX has an internal
	 * delay (added by the GENET block), TX delay comes from board
	 * PCB traces. So: RGMII_MODE_EN=1, ID_MODE_DIS=0 (internal RX
	 * delay enabled), RGMII_LINK=1, OOB_DISABLE=0. */
	uint32_t v = genet_read(state, EXT_RGMII_OOB_CTRL);

	v |= RGMII_LINK | RGMII_MODE_EN;
	v &= ~OOB_DISABLE;
	v &= ~ID_MODE_DIS;

	genet_write(state, EXT_RGMII_OOB_CTRL, v);
}


/* --- Link-state callback ---------------------------------------- */

static void genet_setLinkState(void *arg, int state_up)
{
	struct netif *netif = arg;
	genet_state_t *state = netif->state;
	int full_duplex = 0;
	int speed;

	if (!state_up) {
		genet_printf(state, "link down");
		netif_set_link_down(netif);
		return;
	}

	speed = ephy_linkSpeed(&state->phy, &full_duplex);
	genet_printf(state, "link up: %d Mbps %s-duplex",
		speed, full_duplex ? "full" : "half");

	/* Tier 1 stops here — we don't program UMAC_CMD.SPEED / RX_EN /
	 * TX_EN because there are no rings to fill yet. Tier 2 adds TX,
	 * Tier 3 adds RX, then this callback will also program the MAC
	 * for the negotiated speed/duplex. */

	netif_set_link_up(netif);
}


/* --- linkoutput / media ----------------------------------------- */

static err_t genet_linkOutput(struct netif *netif, struct pbuf *p)
{
	(void)netif;
	(void)p;
	/* Tier 1: no TX path. Drop with "interface down" so lwIP knows the
	 * link layer isn't ready. */
	return ERR_IF;
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

	/* Read firmware-pre-programmed MAC before reset (UMAC reset may
	 * stomp on UMAC_MAC0/MAC1). */
	genet_readMac(state);
	genet_printf(state, "MAC %02x:%02x:%02x:%02x:%02x:%02x",
		state->mac[0], state->mac[1], state->mac[2],
		state->mac[3], state->mac[4], state->mac[5]);

	err = genet_resetUmac(state);
	if (err < 0) {
		return err;
	}

	/* Restore MAC after reset. */
	genet_writeMac(state);

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
