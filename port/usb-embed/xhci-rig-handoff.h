/*
 * Phoenix-RTOS — Raspberry Pi 4 USB (VL805 xHCI)
 *
 * Rig-bring-up handoff: shared contract between the proven inline xHCI
 * bring-up in port/diag-udp.c (the 'X' diag rig, which enumerates a USB
 * hub end-to-end from this same worker context) and the framework HCD in
 * phoenix-rtos-devices/usb/xhci/xhci.c (whose own xhci_init helpers fail
 * to post the first command-completion event despite byte-matching the
 * rig's register sequence — see docs/notes/2026-05-30-usb-rig-bringup-
 * build-plan.md).
 *
 * Stage 1 of "build USB on the rig's path": xhci_init (behind the
 * XHCI_USE_RIG_BRINGUP env gate) calls diag_xhci_rigBringupHandoff() to
 * bring the controller to a verified-RUNNING state (HCRST -> rings ->
 * R/S=1 -> No-Op completion landed), then adopts these live handles into
 * its xhci_t and resumes the framework at EnableSlot. The decisive test:
 * does the framework's command/event path work on a controller the rig
 * brought up?
 *
 * Copyright 2026 Phoenix Systems
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef XHCI_RIG_HANDOFF_H
#define XHCI_RIG_HANDOFF_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
	/* MMIO window (VL805 BAR0) + decoded register-block offsets. */
	void *mmio;        /* mapped MMIO base VA (caller must NOT munmap) */
	size_t mmioSize;
	uint8_t caplength; /* operational regs = mmio + caplength */
	uint32_t rtsoff;   /* runtime regs   = mmio + rtsoff */
	uint32_t dboff;    /* doorbell array = mmio + dboff */

	/* Controller capability fields the framework re-derives. */
	uint32_t nslots;   /* HCSPARAMS1 MaxSlots (for slot-id validation) */
	uint32_t nports;
	unsigned ac64 : 1; /* HCCPARAMS1 AC64 */

	/* Live DMA structures, brought up + verified, ownership transferred
	 * to the caller (the rig does NOT munmap them). VA + PA each. */
	void *dcbaa;
	uint64_t dcbaaPhys;
	void *cmdRing;             /* command ring page (VA) */
	uint64_t cmdRingPhys;
	uint32_t cmdRingCount;     /* TRBs in the command ring */
	uint32_t cmdCycleState;    /* producer cycle state for the next cmd */
	void *eventRing;
	uint64_t eventRingPhys;
	uint32_t eventRingTrbs;
	uint32_t eventCycleState;
	void *erst;
	uint64_t erstPhys;
	void *scratchpadArray;
	uint64_t scratchpadArrayPhys;
	uint32_t nscratchpad;
} xhci_rig_handoff_t;

/*
 * Bring the VL805 xHCI controller up to a verified-RUNNING state using the
 * proven rig sequence, retrying the whole bring-up up to 8x (the rig is
 * ~50%/attempt due to bridge flakiness). On success returns 0 and fills
 * *out with live handles (caller owns the DMA memory; do not munmap on
 * the success path). Returns negative on failure after all retries.
 *
 * NOTE: hands off a FRESH, unused command ring (cmdCycleState=1, dequeue
 * at TRB[0]) so the framework's cmdExec (which always uses cmdRingTrbs[0]
 * and re-publishes CRCR) is consistent. The No-Op verification is done on
 * a throwaway ring that is munmap'd before returning.
 */
int diag_xhci_rigBringupHandoff(xhci_rig_handoff_t *out);

#endif /* XHCI_RIG_HANDOFF_H */
