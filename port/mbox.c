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

#include "sys_sync.h"

#include <pthread.h>
#include <sys/threads.h>
#include <sys/time.h>
#include <sys/mman.h> /* va2pa — TODO(#129) corruption-PA diagnostic */
#include <sys/debug.h> /* debug() — TODO(#129) atomic single-syscall line (printf garbles/drops) */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>


err_t sys_mbox_new(sys_mbox_t *mbox, int size)
{
	if (!mbox)
		return ERR_ARG;

	if (pthread_mutex_init(&mbox->lock, NULL) != 0)
		return ERR_MEM;

	if (sys_sync_condInit(&mbox->push_cond) != 0) {
		(void)pthread_mutex_destroy(&mbox->lock);
		return ERR_MEM;
	}

	if (sys_sync_condInit(&mbox->pop_cond) != 0) {
		(void)pthread_cond_destroy(&mbox->push_cond);
		(void)pthread_mutex_destroy(&mbox->lock);
		return ERR_MEM;
	}

	mbox->ring = calloc(size, sizeof(*mbox->ring));
	if (!mbox->ring) {
		(void)pthread_cond_destroy(&mbox->pop_cond);
		(void)pthread_cond_destroy(&mbox->push_cond);
		(void)pthread_mutex_destroy(&mbox->lock);
		return ERR_MEM;
	}

	mbox->sz = size;
	mbox->head = mbox->tail = 0;

	return ERR_OK;
}


void sys_mbox_free(sys_mbox_t *mbox)
{
	free(mbox->ring);
	(void)pthread_cond_destroy(&mbox->pop_cond);
	(void)pthread_cond_destroy(&mbox->push_cond);
	(void)pthread_mutex_destroy(&mbox->lock);
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

	/* Every post, not only the empty -> non-empty one: with several fetchers
	 * asleep, two quick posts would otherwise wake one and strand a message.
	 * Free when nobody waits (no system call). Under the lock, as all signals. */
	(void)pthread_cond_signal(&mbox->push_cond);

	mbox->ring[mbox->tail] = msg;
	mbox->tail = WRAP(mbox, tail);
	return 1;
}


err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
	int done;

	(void)pthread_mutex_lock(&mbox->lock);
	done = mbox_trypost(mbox, msg);
	(void)pthread_mutex_unlock(&mbox->lock);

	return done ? ERR_OK : ERR_WOULDBLOCK;
}


int sys_mbox_trypost_coalesce(sys_mbox_t *mbox, void *msg, sys_mbox_merge_fn merge)
{
	int done;

	(void)pthread_mutex_lock(&mbox->lock);

	/* Try to merge onto the newest still-queued entry before checking for a
	 * free slot: a full mbox whose tail is mergeable still absorbs `msg`
	 * (turning the would-be ERR_MEM/tcp_fasttmr re-present into an append),
	 * which is exactly the backlog case this path optimizes. */
	if (!mbox_is_empty(mbox)) {
		size_t last = (mbox->tail == 0) ? (mbox->sz - 1) : (mbox->tail - 1);
		if (merge(mbox->ring[last], msg)) {
			(void)pthread_mutex_unlock(&mbox->lock);
			return SYS_MBOX_COALESCED;
		}
	}

	done = mbox_trypost(mbox, msg);
	(void)pthread_mutex_unlock(&mbox->lock);

	return done ? SYS_MBOX_POSTED : SYS_MBOX_FULL;
}


void sys_mbox_post(sys_mbox_t *mbox, void *msg)
{
	(void)pthread_mutex_lock(&mbox->lock);

	while (!mbox_trypost(mbox, msg))
		(void)pthread_cond_wait(&mbox->pop_cond, &mbox->lock);

	(void)pthread_mutex_unlock(&mbox->lock);
}


static int mbox_tryfetch(sys_mbox_t *mbox, void **msg)
{
	if (mbox_is_empty(mbox))
		return 0;

	/* Every fetch, for the same reason as in mbox_trypost() */
	(void)pthread_cond_signal(&mbox->pop_cond);

	/* TODO(#121): the mbox struct has been seen corrupted during USB enumeration
	 * (a libc-heap overflow, likely USB-side, clobbers ring/head -> a wild
	 * ring[head] load faulted in mbox_tryfetch). Validate before dereferencing:
	 * log the corrupt state (clue to the writer) and recover (report empty)
	 * instead of crashing the lwip process. This is a survive-not-crash guard,
	 * not the root-cause fix. */
	if ((mbox->ring == NULL) || (mbox->sz == 0) || (mbox->head >= mbox->sz)) {
		/* Rate-limited: once corrupted, every poll re-detects it and the flood
		 * would back-pressure the UART. Warn once, then recover as empty. */
		static unsigned corruptCount = 0u;
		if (corruptCount == 0u) {
			debug("mbox: ring corrupted (ring/sz/head invalid); recovering as empty\n");
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

	(void)pthread_mutex_lock(&mbox->lock);
	done = mbox_tryfetch(mbox, msg);
	(void)pthread_mutex_unlock(&mbox->lock);

	return done ? 0 : SYS_MBOX_EMPTY;
}


u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout_ms)
{
	struct timespec since = { 0 }, deadline;
	int waited = 0, expired = 0, found;

	(void)pthread_mutex_lock(&mbox->lock);

	found = mbox_tryfetch(mbox, msg);
	if (!found) {
		sys_sync_deadline(&since, &deadline, timeout_ms);
		waited = 1;

		while (!(found = mbox_tryfetch(mbox, msg)) && !expired)
			expired = sys_sync_wait(&mbox->push_cond, &mbox->lock, timeout_ms, &deadline);
	}

	(void)pthread_mutex_unlock(&mbox->lock);

	if (!found)
		return SYS_ARCH_TIMEOUT;

	/* A message already queued took 0 ms: no clock read on the fast path */
	return waited ? sys_sync_elapsedMs(&since) : 0;
}
