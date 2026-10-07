/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - helpers shared by the semaphores and mailboxes
 *
 * Copyright 2026 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PHOENIX_LWIP_SYS_SYNC_H_
#define PHOENIX_LWIP_SYS_SYNC_H_

#include "arch/sys_arch.h"
#include "lwip/sys.h"

#include <errno.h>
#include <pthread.h>
#include <time.h>


/* Timed waits use absolute CLOCK_MONOTONIC deadlines, unaffected by settimeofday() */
static inline int sys_sync_condInit(pthread_cond_t *cond)
{
	pthread_condattr_t attr;
	int err;

	err = pthread_condattr_init(&attr);
	if (err == 0) {
		err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
		if (err == 0) {
			err = pthread_cond_init(cond, &attr);
		}
		(void)pthread_condattr_destroy(&attr);
	}

	return err;
}


/* Reads the clock into *since and sets *deadline `ms` milliseconds later */
static inline void sys_sync_deadline(struct timespec *since, struct timespec *deadline, u32_t ms)
{
	(void)clock_gettime(CLOCK_MONOTONIC, since);

	deadline->tv_sec = since->tv_sec + (time_t)(ms / 1000U);
	deadline->tv_nsec = since->tv_nsec + (long)(ms % 1000U) * 1000000L;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
}


/* Milliseconds since *since, rounded; never SYS_ARCH_TIMEOUT */
static inline u32_t sys_sync_elapsedMs(const struct timespec *since)
{
	struct timespec now;
	long long ms;

	(void)clock_gettime(CLOCK_MONOTONIC, &now);

	ms = ((long long)now.tv_sec - since->tv_sec) * 1000LL + (now.tv_nsec - since->tv_nsec + 500000L) / 1000000L;
	if (ms < 0) {
		return 0;
	}

	return (ms >= (long long)SYS_ARCH_TIMEOUT) ? (SYS_ARCH_TIMEOUT - 1U) : (u32_t)ms;
}


/* Waits on `cond`: forever if `timeout` is 0, else until `deadline`.
 * Returns nonzero when the deadline has passed. The caller re-checks its
 * predicate either way: a signal can land between the timeout and the
 * reacquisition of the lock, and wake-ups may be spurious. */
static inline int sys_sync_wait(pthread_cond_t *cond, pthread_mutex_t *lock, u32_t timeout, const struct timespec *deadline)
{
	if (timeout == 0U) {
		(void)pthread_cond_wait(cond, lock);
		return 0;
	}

	return (pthread_cond_timedwait(cond, lock, deadline) == ETIMEDOUT) ? 1 : 0;
}

#endif
