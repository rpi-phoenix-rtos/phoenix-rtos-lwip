/*
 * Phoenix-RTOS --- LwIP port
 *
 * BCM2711 GENET v5 register map (Pi 4)
 *
 * Copyright 2026 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Block layout in the 64 KiB GENET MMIO window:
 *   0x0000  SYS         system / revision / flush
 *   0x0040  GR_BRIDGE   global bridge control
 *   0x0080  EXT         external (PHY reset, RGMII OOB, EEE)
 *   0x0200  INTRL2_0    interrupt level-2 set 0 (general / RX-dflt / TX-dflt)
 *   0x0240  INTRL2_1    interrupt level-2 set 1 (priority rings)
 *   0x0300  RBUF        RX buffer / packet filters
 *   0x0800  UMAC        UMAC (Unified MAC) — incl. CMD, MAC0/1
 *   0x0E14  UMAC_MDIO   MDIO command register (single-word interface on v5)
 *   0x2000  RDMA        RX DMA registers
 *   0x4000  TDMA        TX DMA registers
 *   0xFC00  HFB         hardware filter blocks
 *
 * All offsets in bytes from the GENET MMIO base.
 *
 * Pi 4 / BCM2711: GENET sits at ARM-side phys 0xFD580000, size 64 KiB.
 * Two SPIs: 189 (general) + 190 (ring); both level-high.
 *
 * Tier 1 needs only SYS, EXT, UMAC, and UMAC_MDIO. The rest are
 * declared here so subsequent tiers don't need to extend this header.
 */
#ifndef PHOENIX_BCM_GENET_REGS_H_
#define PHOENIX_BCM_GENET_REGS_H_

#include <stdint.h>


/* Block bases within the GENET window. */
#define GENET_SYS_OFF        0x0000u
#define GENET_GR_BRIDGE_OFF  0x0040u
#define GENET_EXT_OFF        0x0080u
#define GENET_INTRL2_0_OFF   0x0200u
#define GENET_INTRL2_1_OFF   0x0240u
#define GENET_RBUF_OFF       0x0300u
#define GENET_UMAC_OFF       0x0800u
#define GENET_RDMA_OFF       0x2000u
#define GENET_TDMA_OFF       0x4000u
#define GENET_HFB_REGS_OFF   0xFC00u


/* --- SYS block (0x0000 + ...) ----------------------------------- */

#define SYS_REV_CTRL         (GENET_SYS_OFF + 0x00u)
#define SYS_PORT_CTRL        (GENET_SYS_OFF + 0x04u)
#define SYS_RBUF_FLUSH_CTRL  (GENET_SYS_OFF + 0x08u)
#define SYS_TBUF_FLUSH_CTRL  (GENET_SYS_OFF + 0x0Cu)

/* SYS_PORT_CTRL: selects which physical interface the MAC drives.
 * Pi 4 uses an external Broadcom GPHY via RGMII. */
#define PORT_MODE_INT_EPHY   0x00u
#define PORT_MODE_INT_GPHY   0x01u
#define PORT_MODE_EXT_EPHY   0x02u
#define PORT_MODE_EXT_GPHY   0x03u
#define PORT_MODE_EXT_RVMII  0x04u

/* SYS_REV_CTRL bit fields: GENET v5 reports major=6 in bits 24..27
 * (the silicon-IP increment counter); we accept either v5 or v6 by
 * masking. See Circle and Linux bcmgenet_check_rev. */
#define SYS_REV_CTRL_MAJOR_MASK   0x0F000000u
#define SYS_REV_CTRL_MAJOR_SHIFT  24
#define SYS_REV_CTRL_MINOR_MASK   0x00F00000u
#define SYS_REV_CTRL_MINOR_SHIFT  20

/* SYS_RBUF_FLUSH_CTRL / SYS_TBUF_FLUSH_CTRL: bit 1 = reset the RX/TX
 * datapath FIFOs. Used during reset_umac. */
#define SYS_BUF_FLUSH_RESET  (1u << 1)


/* --- EXT block (0x0080 + ...) ----------------------------------- */

#define EXT_EXT_PWR_MGMT     (GENET_EXT_OFF + 0x00u)
#define EXT_RGMII_OOB_CTRL   (GENET_EXT_OFF + 0x0Cu)
#define EXT_GPHY_CTRL        (GENET_EXT_OFF + 0x1Cu)

/* EXT_RGMII_OOB_CTRL bits used during PHY bring-up. */
#define RGMII_LINK           (1u << 4)
#define OOB_DISABLE          (1u << 5)
#define RGMII_MODE_EN        (1u << 6)  /* "RGMII mode enable" — required for RGMII */
#define ID_MODE_DIS          (1u << 16) /* "internal delay mode disable" */

/* EXT_GPHY_CTRL bits used to hard-reset the integrated/external PHY.
 * Pi 4 has an external BCM54213PE — the EXT_GPHY_RESET strobe still
 * routes a GPIO reset to the PHY through the GENET block. */
#define EXT_GPHY_RESET       (1u << 5)
#define EXT_CK25_DIS         (1u << 4)
#define EXT_CFG_IDDQ_BIAS    (1u << 0)
#define EXT_CFG_PWR_DOWN     (1u << 1)
#define EXT_ENERGY_DET_MASK  (0xFu << 12)


/* --- RBUF block (0x0300 + ...) ---------------------------------- */
/*
 * Receive buffer interface — sits between UMAC and RDMA. Linux/U-Boot
 * touch RBUF_CTRL.ALIGN_2B (so the L3 header lands 4-byte-aligned) and
 * write 1 to RBUF_TBUF_SIZE_CTRL during DMA init.
 */
#define RBUF_CTRL            (GENET_RBUF_OFF + 0x00u)
#define RBUF_CHK_CTRL        (GENET_RBUF_OFF + 0x14u)
#define RBUF_TBUF_SIZE_CTRL  (GENET_RBUF_OFF + 0xB4u)

/* RBUF_CTRL */
#define RBUF_64B_EN          (1u << 0)
#define RBUF_ALIGN_2B        (1u << 1)

/* RBUF_CHK_CTRL — Linux always sets RXCHK_EN + L3_PARSE_DIS. The Linux v5
 * init_umac is the only public source that documents these as required;
 * U-Boot and Circle either omit or never re-read RBUF, which masked the
 * dependency on these bits. */
#define RBUF_RXCHK_EN        (1u << 0)
#define RBUF_SKIP_FCS        (1u << 4)
#define RBUF_L3_PARSE_DIS    (1u << 5)


/* --- UMAC block (0x0800 + ...) ---------------------------------- */

#define UMAC_HD_BKP_CTRL     (GENET_UMAC_OFF + 0x004u)
#define UMAC_CMD             (GENET_UMAC_OFF + 0x008u)
#define UMAC_MAC0            (GENET_UMAC_OFF + 0x00Cu)
#define UMAC_MAC1            (GENET_UMAC_OFF + 0x010u)
#define UMAC_MAX_FRAME_LEN   (GENET_UMAC_OFF + 0x014u)
#define UMAC_TX_FLUSH        (GENET_UMAC_OFF + 0x334u)
#define UMAC_MIB_START       (GENET_UMAC_OFF + 0x400u)

/* UMAC_CMD bit fields — common across GENETv4/v5. */
#define CMD_TX_EN            (1u << 0)
#define CMD_RX_EN            (1u << 1)
#define CMD_SPEED_SHIFT      2
#define CMD_SPEED_MASK       (3u << CMD_SPEED_SHIFT)
#define CMD_SPEED_10         (0u << CMD_SPEED_SHIFT)
#define CMD_SPEED_100        (1u << CMD_SPEED_SHIFT)
#define CMD_SPEED_1000       (2u << CMD_SPEED_SHIFT)
#define CMD_PROMISC          (1u << 4)
#define CMD_PAD_EN           (1u << 5)
#define CMD_CRC_FWD          (1u << 6)
#define CMD_PAUSE_FWD        (1u << 7)
#define CMD_RX_PAUSE_IGNORE  (1u << 8)
#define CMD_TX_ADDR_INS      (1u << 9)
#define CMD_HD_EN            (1u << 10) /* half-duplex */
#define CMD_SW_RESET         (1u << 13)
#define CMD_LCL_LOOP_EN      (1u << 15)
#define CMD_AUTO_CONFIG      (1u << 22)
#define CMD_CNTL_FRM_EN      (1u << 23)
#define CMD_NO_LEN_CHK       (1u << 24)
#define CMD_RMT_LOOP_EN      (1u << 25)
#define CMD_PRBL_EN          (1u << 27)
#define CMD_TX_PAUSE_IGNORE  (1u << 28)
#define CMD_TX_RX_EN_CFG     (1u << 29)
#define CMD_LCL_LOOP_EN_M    (1u << 31)


/* --- MDIO (absolute offset 0x0E14, single-register interface) --- */

#define UMAC_MDIO_CMD        0x0E14u

#define MDIO_DATA_MASK       0x0000FFFFu  /* read result is in bits 0..15 */
#define MDIO_REG_SHIFT       16            /* phy register (5 bits) */
#define MDIO_REG_MASK        (0x1Fu << MDIO_REG_SHIFT)
#define MDIO_PMD_SHIFT       21            /* phy MDIO address (5 bits) */
#define MDIO_PMD_MASK        (0x1Fu << MDIO_PMD_SHIFT)
#define MDIO_CMD_WR          (1u << 26)
#define MDIO_CMD_RD          (1u << 27)
#define MDIO_FAIL            (1u << 28)
#define MDIO_READ_FAILED     (1u << 29)
#define MDIO_START_BUSY      (1u << 29)   /* alias on GENETv5: bit 29 is
                                            "start/busy"; controller clears
                                            when MDIO transaction completes.
                                            (Some references use bit 30 — to
                                            be confirmed against hardware in
                                            Tier 1.) */


/* --- INTRL2_0 / INTRL2_1 (0x0200 / 0x0240 + ...) --------------- */
/* Tier 1 doesn't enable IRQs; declarations here for later. */

#define INTRL2_CPU_STAT      0x00u
#define INTRL2_CPU_SET       0x04u
#define INTRL2_CPU_CLEAR     0x08u
#define INTRL2_CPU_MASK_STAT 0x0Cu
#define INTRL2_CPU_MASK_SET  0x10u
#define INTRL2_CPU_MASK_CLEAR 0x14u

/* INTRL2_0 sources we'll care about in Tier 4+ */
#define INTRL2_0_RX_DMA_DONE (1u << 13)
#define INTRL2_0_TX_DMA_DONE (1u << 16)
#define INTRL2_0_LINK_UP     (1u << 4)
#define INTRL2_0_LINK_DOWN   (1u << 5)


/* --- DMA layout (Tier 2+) -------------------------------------- */
/*
 * GENET TDMA / RDMA MMIO map:
 *
 *   0x4000  TX buffer descriptors (256 × 12 B = 0xC00)
 *   0x4C00  per-TX-ring control (17 × 0x40 = 0x440)
 *   0x5040  global TDMA control
 *   ...
 *   (RX layout mirrors, starting at GENET_RDMA_OFF = 0x2000)
 *
 * Cross-reference: U-Boot drivers/net/bcmgenet.c, Linux bcmgenet.h.
 * Each BD is 3 little-endian words: length+status, addr-lo, addr-hi.
 */
#define GENET_DMA_DESC_SIZE  12u
#define GENET_TOTAL_DESC     256u
#define GENET_DEFAULT_RING   16u   /* default TX queue (= DEFAULT_Q) */
#define GENET_DMA_RING_SIZE  0x40u
#define GENET_DMA_RINGS_SIZE (GENET_DMA_RING_SIZE * (GENET_DEFAULT_RING + 1))

#define GENET_TX_DESCS_OFF   GENET_TDMA_OFF                    /* 0x4000 */
#define GENET_TX_RINGS_OFF   (GENET_TX_DESCS_OFF + GENET_TOTAL_DESC * GENET_DMA_DESC_SIZE) /* 0x4C00 */
#define GENET_TDMA_REGS_OFF  (GENET_TX_RINGS_OFF + GENET_DMA_RINGS_SIZE)  /* 0x5040 */

/* RDMA mirrors TDMA's layout one MMIO block lower. */
#define GENET_RX_DESCS_OFF   GENET_RDMA_OFF                    /* 0x2000 */
#define GENET_RX_RINGS_OFF   (GENET_RX_DESCS_OFF + GENET_TOTAL_DESC * GENET_DMA_DESC_SIZE) /* 0x2C00 */
#define GENET_RDMA_REGS_OFF  (GENET_RX_RINGS_OFF + GENET_DMA_RINGS_SIZE)  /* 0x3040 */

/* Per-ring control register offsets. **TDMA and RDMA have MIRRORED
 * layouts** for the producer/consumer pair (the SW side and the HW side
 * are swapped):
 *
 *               TDMA (SW produces)        RDMA (HW produces)
 *   0x00        TDMA_READ_PTR             RDMA_WRITE_PTR
 *   0x08        TDMA_CONS_INDEX (HW)      RDMA_PROD_INDEX (HW)
 *   0x0C        TDMA_PROD_INDEX (SW)      RDMA_CONS_INDEX (SW)
 *   0x10..0x24  identical (BUF_SIZE, START_ADDR, END_ADDR, MBUF_DONE)
 *   0x28        TDMA_FLOW_PERIOD          RDMA_XON_XOFF_THRESH
 *   0x2C        TDMA_WRITE_PTR            RDMA_READ_PTR
 *
 * Using the TDMA offsets on the RDMA side (which my driver did for
 * weeks) means reading the SW-written CONS_INDEX as if it were the
 * HW-written PROD_INDEX — explaining "PROD never advances" while
 * HW happily wrote frame status into the BDs.
 *
 * Reference: Linux drivers/net/ethernet/broadcom/genet/bcmgenet.h.
 */

/* TDMA per-ring (SW produces, HW consumes) */
#define GENET_TDMA_RING_READ_PTR    0x00u
#define GENET_TDMA_RING_CONS_INDEX  0x08u  /* HW writes after TX */
#define GENET_TDMA_RING_PROD_INDEX  0x0Cu  /* SW writes to kick TX */
#define GENET_TDMA_RING_BUF_SIZE    0x10u
#define GENET_TDMA_RING_START_ADDR  0x14u
#define GENET_TDMA_RING_END_ADDR    0x1Cu
#define GENET_TDMA_RING_MBUF_DONE   0x24u
#define GENET_TDMA_RING_FLOW_PERIOD 0x28u
#define GENET_TDMA_RING_WRITE_PTR   0x2Cu

/* RDMA per-ring (HW produces, SW consumes). Note: indices SWAPPED
 * from TDMA layout — see the table above. */
#define GENET_RDMA_RING_WRITE_PTR   0x00u
#define GENET_RDMA_RING_PROD_INDEX  0x08u  /* HW writes after RX */
#define GENET_RDMA_RING_CONS_INDEX  0x0Cu  /* SW writes when buffers returned */
#define GENET_RDMA_RING_BUF_SIZE    0x10u
#define GENET_RDMA_RING_START_ADDR  0x14u
#define GENET_RDMA_RING_END_ADDR    0x1Cu
#define GENET_RDMA_RING_MBUF_DONE   0x24u
#define GENET_RDMA_RING_XON_XOFF    0x28u
#define GENET_RDMA_RING_READ_PTR    0x2Cu

/* Linux's RX flow-control defaults (DMA_FC_THRESH_{LO,HI},
 * DMA_XOFF_THRESHOLD_SHIFT). Used together as
 *   (LO << SHIFT) | HI
 * so XOFF triggers at LO descriptors remaining, XON resumes at HI. */
#define GENET_DMA_FC_THRESH_LO      5u
#define GENET_DMA_FC_THRESH_HI      (GENET_TOTAL_DESC >> 4)
#define GENET_DMA_XOFF_THRESH_SHIFT 16

/* Global TDMA control registers. */
#define GENET_TDMA_RING_CFG         0x00u  /* per-ring enable bitmap */
#define GENET_TDMA_CTRL             0x04u  /* TDMA enable + default-queue */
#define GENET_TDMA_STATUS           0x08u  /* per-ring disabled bitmap (mirror of CTRL when stopped) */
#define GENET_TDMA_SCB_BURST_SIZE   0x0Cu

#define GENET_DMA_TIMEOUT_US        100000u  /* Linux DMA_TIMEOUT_VAL */

#define GENET_TDMA_CTRL_TDMA_EN     (1u << 0)
#define GENET_TDMA_CTRL_RBUF_EN_LSB 1u      /* per-ring enable starts here */

#define GENET_DMA_DEFAULT_BURST     0x08u   /* 8 64-bit words per burst */

/* Per-BD status/length word bits (low 16 = flags, high 12 = length). */
#define BD_LEN_SHIFT         16
#define BD_LEN_MASK          (0xFFFu << BD_LEN_SHIFT)
#define BD_STATUS_OWN        (1u << 15)   /* hardware owns the BD */
#define BD_STATUS_EOP        (1u << 14)   /* end-of-packet */
#define BD_STATUS_SOP        (1u << 13)   /* start-of-packet */
#define BD_STATUS_WRAP       (1u << 12)   /* last BD in the ring */
#define BD_STATUS_TX_CRC     (1u << 6)    /* auto-append FCS */
#define BD_STATUS_TX_CSUM    (1u << 4)    /* hardware checksum */

/* RX-side BD status bits (low 7 = packet-filter / error flags). */
#define BD_STATUS_RX_LG          (1u << 4)  /* frame too long */
#define BD_STATUS_RX_NO          (1u << 3)  /* alignment error */
#define BD_STATUS_RX_RXER        (1u << 2)  /* RX error */
#define BD_STATUS_RX_CRC_ERROR   (1u << 1)  /* CRC error */
#define BD_STATUS_RX_OV          (1u << 0)  /* overflow */
#define GENET_RX_STATUS_ERROR_MASK \
	(BD_STATUS_RX_LG | BD_STATUS_RX_NO | BD_STATUS_RX_RXER | \
	 BD_STATUS_RX_CRC_ERROR | BD_STATUS_RX_OV)

/* RBUF_64B_EN + RBUF_ALIGN_2B together prepend 66 bytes before the
 * actual Ethernet frame in every RX buffer:
 *   buf[0..1]   2-byte alignment pad (so the IP header lands 4-byte
 *               aligned at buf[80] = 66 + 14)
 *   buf[2..65]  64-byte GENET status block
 *   buf[66..]   Ethernet frame (dst MAC, src MAC, ethertype, payload)
 *
 * The length field in the BD status word counts all 66 bytes; subtract
 * before handing the payload to lwIP.
 *
 * Found by observing a captured RX#0 frame had dst MAC reading as
 * 00:00:01:00:5e:00 when read at buf[64]: the leading 00:00 is the
 * alignment pad, and the real multicast dst 01:00:5e:00:XX:XX starts
 * at buf[66].
 */
#define GENET_RX_STATUS_PREFIX   66u

#define GENET_MAX_FRAME      2048u /* per-buffer slot size */
#define GENET_BUF_ALIGN      32u   /* skb alignment from Linux SKB_ALIGNMENT */


#endif /* PHOENIX_BCM_GENET_REGS_H_ */
