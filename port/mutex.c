/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - mutex wrappers
 *
 * Copyright 2018, 2026 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/sys_arch.h"
#include "lwip/err.h"

#include <pthread.h>


/* A default pthread mutex: a user-space lock with no system call when free.
 * Its main user is the TCPIP core lock (LWIP_TCPIP_CORE_LOCKING). */
err_t sys_mutex_new(sys_mutex_t *mutex)
{
	if (pthread_mutex_init(&mutex->mutex, NULL) != 0) {
		return ERR_MEM;
	}

	mutex->valid = 1;

	return ERR_OK;
}


void sys_mutex_free(sys_mutex_t *mutex)
{
	if (mutex != NULL) {
		(void)pthread_mutex_destroy(&mutex->mutex);
	}
}


void sys_mutex_lock(sys_mutex_t *mutex)
{
	(void)pthread_mutex_lock(&mutex->mutex);
}


void sys_mutex_unlock(sys_mutex_t *mutex)
{
	(void)pthread_mutex_unlock(&mutex->mutex);
}
