/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - mailboxes
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "arch/sys_arch.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include <sys/threads.h>
#include <sys/time.h>
#include <sys/mman.h> /* va2pa — TODO(#129) corruption-PA diagnostic */
#include <sys/debug.h> /* debug() — TODO(#129) atomic single-syscall line (printf garbles/drops) */
#include <stdio.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


err_t sys_mbox_new(sys_mbox_t *mbox, int size)
{
	if (!mbox)
		return ERR_ARG;

	if (mutexCreate(&mbox->lock))
		return ERR_MEM;

	if (condCreate(&mbox->push_cond)) {
		resourceDestroy(mbox->lock);
		return ERR_MEM;
	}

	if (condCreate(&mbox->pop_cond)) {
		resourceDestroy(mbox->push_cond);
		resourceDestroy(mbox->lock);
		return ERR_MEM;
	}

	mbox->ring = calloc(size, sizeof(*mbox->ring));
	if (!mbox->ring) {
		resourceDestroy(mbox->pop_cond);
		resourceDestroy(mbox->push_cond);
		resourceDestroy(mbox->lock);
		return ERR_MEM;
	}

	mbox->sz = size;
	mbox->head = mbox->tail = 0;

	/* TODO(#121): log mbox + ring at allocation so a later wild-load fault in
	 * mbox_tryfetch is decisive: if the in-tryfetch guard fires, head was
	 * corrupted (ring intact); if it faults anyway, compare the exception far
	 * against these ring values to confirm ring itself was overwritten. */
	/* TODO(#129): also print PHYSICAL addresses. mboxes are created early (clean
	 * UART, before the USB enumeration flood) and live in pinned heap, so this is
	 * the reliable way to learn the victim's PA. Compare against the USB DMA pool
	 * PAs (xhci DMAMAP, ~0x32xxxxx): if a mbox/ring PA falls in that range, the
	 * uncached USB pool physically ALIASES lwIP's cached heap (the #26 pmap bug)
	 * and the controller's DMA corrupts it — independent of the corruption firing. */
	{
		char d[128];
		snprintf(d, sizeof(d), "mbox NEW: mbox=%p (pa=0x%llx) ring=%p (pa=0x%llx) sz=%d\n",
			(void *)mbox, (unsigned long long)va2pa((void *)mbox),
			(void *)mbox->ring, (unsigned long long)va2pa((void *)mbox->ring), size);
		debug(d);
	}

	return ERR_OK;
}


/* TODO(#129) free-vs-steal forensic: record recently-freed mbox structs in a
 * small ring (no per-free debug() flood). When the corruption detector fires it
 * checks whether the victim is in here: present ⇒ the mbox was torn down and its
 * memp slot reused = use-after-free in the poll path (fix = lifetime/invalidate);
 * absent ⇒ a LIVE mbox's memory was stolen = heap/allocator corruption. */
void *mbox_diagFreed[32];
volatile unsigned mbox_diagFreedIdx;

void sys_mbox_free(sys_mbox_t *mbox)
{
	mbox_diagFreed[mbox_diagFreedIdx & 31u] = (void *)mbox;
	mbox_diagFreedIdx++;
	free(mbox->ring);
	resourceDestroy(mbox->pop_cond);
	resourceDestroy(mbox->push_cond);
	resourceDestroy(mbox->lock);
}


#define WRAP(m,t) ((m)->t + 1 < (m)->sz ? (m)->t + 1 : 0)


static int mbox_is_empty(sys_mbox_t *mbox)
{
	return mbox->head == mbox->tail;
}


static int mbox_is_full(sys_mbox_t *mbox)
{
	return WRAP(mbox, tail) == mbox->head;
}


static int mbox_trypost(sys_mbox_t *mbox, void *msg)
{
	if (mbox_is_full(mbox))
		return 0;

	if (mbox_is_empty(mbox))
		condSignal(mbox->push_cond);

	mbox->ring[mbox->tail] = msg;
	mbox->tail = WRAP(mbox, tail);
	return 1;
}


err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
	int done;

	mutexLock(mbox->lock);
	done = mbox_trypost(mbox, msg);
	mutexUnlock(mbox->lock);

	return done ? ERR_OK : ERR_WOULDBLOCK;
}


void sys_mbox_post(sys_mbox_t *mbox, void *msg)
{
	mutexLock(mbox->lock);

	while (!mbox_trypost(mbox, msg))
		condWait(mbox->pop_cond, mbox->lock, 0);

	mutexUnlock(mbox->lock);
}


static int mbox_tryfetch(sys_mbox_t *mbox, void **msg)
{
	if (mbox_is_empty(mbox))
		return 0;

	if (mbox_is_full(mbox))
		condSignal(mbox->pop_cond);

	/* TODO(#121): the mbox struct has been seen corrupted during USB enumeration
	 * (a libc-heap overflow, likely USB-side, clobbers ring/head -> a wild
	 * ring[head] load faulted in mbox_tryfetch). Validate before dereferencing:
	 * log the corrupt state (clue to the writer) and recover (report empty)
	 * instead of crashing the lwip process. This is a survive-not-crash guard,
	 * not the root-cause fix. */
	if ((mbox->ring == NULL) || (mbox->sz == 0) || (mbox->head >= mbox->sz)) {
		/* TODO(#129): rate-limit — once corrupted, every poll re-detects and the
		 * flood back-pressures the UART (and wedges the host). Print the first few
		 * with the struct's PHYSICAL address: the #121/#129 hunt needs to know
		 * whether va2pa(mbox) lands inside a programmed USB DMA region (DMA overrun)
		 * or nowhere near one (CPU write). va2pa is cheap and the struct is one
		 * cache line, so its PA localises the victim for the overlap test. */
		static unsigned corruptCount = 0u;
		if (corruptCount == 0u) {
			/* ONE atomic debug() line — the victim's PA vs the USB DMA pool
			 * (USBPOOL log) is the DMA-overrun-vs-CPU-write discriminator (#129). */
			char d[128];
			unsigned i;
			volatile uint64_t *w = (volatile uint64_t *)((char *)mbox - 32);
			snprintf(d, sizeof(d), "MBOXPA pa=0x%llx ringpa=0x%llx h=%zu sz=%zu\n",
				(unsigned long long)va2pa((void *)mbox),
				(unsigned long long)va2pa((void *)mbox->ring),
				mbox->head, mbox->sz);
			debug(d);
			/* free-vs-steal verdict: was this victim recently torn down? */
			{
				unsigned k;
				int wasFreed = 0;
				for (k = 0u; k < 32u; k++) {
					if (mbox_diagFreed[k] == (void *)mbox) {
						wasFreed = 1;
						break;
					}
				}
				snprintf(d, sizeof(d), "MBOXFREED=%d (1=UAF-in-poll, 0=live-stolen) frees=%u\n",
					wasFreed, (unsigned)mbox_diagFreedIdx);
				debug(d);
			}
			/* TODO(#129) dump raw memory around the victim struct so the OVERWRITING
			 * data's signature identifies the writer (a recognizable struct/TRB/HID
			 * report, or an adjacent allocation that overflowed). Atomic debug() per
			 * line; window = mbox-32 .. mbox+96 (16 u64). The sys_mbox_t field order
			 * is {lock,push_cond,pop_cond, ring, sz, head, tail,...} so the post-mbox
			 * words show the clobbered ring/sz/head/tail; the pre-mbox words show any
			 * overflow source. */
			for (i = 0u; i < 16u; i++) {
				snprintf(d, sizeof(d), "MBOXDUMP %+d: 0x%016llx\n",
					(int)(i * 8u) - 32, (unsigned long long)w[i]);
				debug(d);
			}
		}
		corruptCount++;
		return 0;
	}

	*msg = mbox->ring[mbox->head];
	mbox->head = WRAP(mbox, head);
	return 1;
}


u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg)
{
	int done;

	mutexLock(mbox->lock);
	done = mbox_tryfetch(mbox, msg);
	mutexUnlock(mbox->lock);

	return done ? 0 : SYS_MBOX_EMPTY;
}


u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout_ms)
{
	time_t since, now, when, timeout;
	int found = 1;

	timeout = timeout_ms * 1000;
	gettime(&now, NULL);
	since = now;
	when = now + timeout;

	mutexLock(mbox->lock);

	while (!mbox_tryfetch(mbox, msg)) {
		condWait(mbox->push_cond, mbox->lock, timeout);
		if (!timeout)
			continue;

		gettime(&now, NULL);
		if (now >= when) {
			found = 0;
			break;
		}
		timeout = when - now;
	}

	mutexUnlock(mbox->lock);

	if (!found)
		return SYS_ARCH_TIMEOUT;

	gettime(&now, NULL);
	return (now - since) / 1000;
}
