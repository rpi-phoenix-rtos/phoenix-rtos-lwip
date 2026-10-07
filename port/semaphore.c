/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - semaphore wrapper
 *
 * Copyright 2018, 2026 Phoenix Systems
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


err_t sys_sem_new(sys_sem_t *sem, u8_t count)
{
	if (pthread_mutex_init(&sem->lock, NULL) != 0) {
		return ERR_MEM;
	}

	if (sys_sync_condInit(&sem->cond) != 0) {
		(void)pthread_mutex_destroy(&sem->lock);
		return ERR_MEM;
	}

	sem->count = count;
	sem->valid = 1;

	return ERR_OK;
}


void sys_sem_free(sys_sem_t *sem)
{
	(void)pthread_cond_destroy(&sem->cond);
	(void)pthread_mutex_destroy(&sem->lock);
}


void sys_sem_signal(sys_sem_t *sem)
{
	(void)pthread_mutex_lock(&sem->lock);
	sem->count++;
	/* Under the lock: the waiter may free the semaphore once it has its unit */
	(void)pthread_cond_signal(&sem->cond);
	(void)pthread_mutex_unlock(&sem->lock);
}


u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout)
{
	struct timespec since = { 0 }, deadline;
	int waited = 0, expired = 0;

	(void)pthread_mutex_lock(&sem->lock);

	if (sem->count == 0U) {
		sys_sync_deadline(&since, &deadline, timeout);

		while ((sem->count == 0U) && (expired == 0)) {
			expired = sys_sync_wait(&sem->cond, &sem->lock, timeout, &deadline);
		}

		if (sem->count == 0U) {
			(void)pthread_mutex_unlock(&sem->lock);
			return SYS_ARCH_TIMEOUT;
		}

		waited = 1;
	}

	sem->count--;
	(void)pthread_mutex_unlock(&sem->lock);

	/* Not waiting at all is 0 ms: no clock read on the fast path */
	return (waited != 0) ? sys_sync_elapsedMs(&since) : 0U;
}
