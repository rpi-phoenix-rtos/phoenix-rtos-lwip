/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer - global lock
 *
 * Copyright 2018, 2026 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "arch/sys_arch.h"

#include <pthread.h>


/* SYS_ARCH_PROTECT. A recursive pthread mutex knows its owner without a system
 * call (a thread-local id where the architecture has TLS, gettid() elsewhere),
 * so protecting a pbuf reference count costs two atomic operations. */
static pthread_mutex_t global_mutex;


void sys_arch_global_lock(void)
{
	(void)pthread_mutex_lock(&global_mutex);
}


void sys_arch_global_unlock(void)
{
	(void)pthread_mutex_unlock(&global_mutex);
}


void init_lwip_global_lock(void)
{
	pthread_mutexattr_t attr;
	int err;

	err = pthread_mutexattr_init(&attr);
	if (err == 0) {
		err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		if (err == 0) {
			err = pthread_mutex_init(&global_mutex, &attr);
		}
		(void)pthread_mutexattr_destroy(&attr);
	}

	if (err != 0) {
		errout(-err, "pthread_mutex_init(global_lock)");
	}
}
