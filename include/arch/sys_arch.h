/*
 * Phoenix-RTOS --- LwIP port
 *
 * LwIP OS mode layer
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef PHOENIX_LWIP_SYS_ARCH_H_
#define PHOENIX_LWIP_SYS_ARCH_H_


#include <sys/threads.h>
#include <pthread.h>
#include <stdint.h>
#include <time.h>


/*
 * Mutexes, semaphores and mailboxes are built on libphoenix's pthread mutexes
 * and condition variables. These are user-space locks (futex based): taking a
 * free one, releasing one nobody waits for and signalling a condition nobody
 * waits on cost one atomic operation each, and the kernel is entered only to
 * sleep or to wake a sleeper. The kernel-handle mutexes used before cost a
 * system call per lock and per unlock, contended or not -- on the NFS-root
 * receive path that was most of the network stack's kernel time.
 *
 * Every wait object signals while holding its lock and touches nothing of the
 * object after the unlock, so the woken thread may free it as soon as it runs
 * (lwIP does that with a netconn's op_completed semaphore).
 */
struct sys_mbox_s
{
	pthread_mutex_t lock;
	pthread_cond_t push_cond, pop_cond;
	size_t sz, head, tail;
	void **ring;
};


struct sys_sem_s
{
	pthread_mutex_t lock;
	pthread_cond_t cond;
	unsigned int count;
	int valid;
};


struct sys_mutex_s
{
	pthread_mutex_t mutex;
	int valid;
};


typedef handle_t sys_thread_t;
typedef struct sys_mutex_s sys_mutex_t;
typedef struct sys_sem_s sys_sem_t;
typedef struct sys_mbox_s sys_mbox_t;


/* A zeroed object is invalid: lwIP tests objects it has never created */
#define sys_mutex_valid(m) ((m)->valid != 0)
#define sys_mutex_set_invalid(m) do (m)->valid = 0; while (0)


#define sys_sem_valid(m) ((m)->valid != 0)
#define sys_sem_set_invalid(m) do (m)->valid = 0; while (0)


#define sys_mbox_valid(m) ((m)->ring != NULL)
#define sys_mbox_set_invalid(m) do (m)->ring = NULL; while (0)


/* Coalescing post for streaming (TCP) receive.
 *
 * Under the mbox lock, if the newest still-queued entry exists and the caller's
 * merge() absorbs `msg` into it, no new ring slot is consumed and no waiter is
 * signalled (the queued entry already signalled readiness when it was posted).
 * Otherwise `msg` is posted as a normal new entry. This lets the TCP recv
 * callback fold back-to-back segments onto a single pbuf chain, cutting the
 * per-segment recvmbox handoff (post/fetch + consumer wakeup) that dominates
 * the socket-recv throughput gap. See docs/inprogress/gigabit-nfs-perf-decision.md
 * (Option B). merge(tail_entry, msg) returns nonzero iff it absorbed msg.
 *
 * Dequeue and this append serialize on the same mbox lock, so there is no
 * producer/consumer race and no lost wakeup (coalesce only runs when non-empty,
 * and sys_arch_mbox_fetch only waits when empty). */
typedef int (*sys_mbox_merge_fn)(void *tail_entry, void *new_msg);

#define SYS_MBOX_POSTED    0    /* posted as a new entry (a waiter is signalled) */
#define SYS_MBOX_COALESCED 1    /* merged onto the queued tail entry; no new slot, no signal */
#define SYS_MBOX_FULL      (-1) /* mbox full and tail unmergeable; nothing posted */

int sys_mbox_trypost_coalesce(sys_mbox_t *mbox, void *msg, sys_mbox_merge_fn merge);


#define sys_msleep(m) usleep((time_t)(m) * 1000)


/* SYS_ARCH_PROTECT: one process-wide lock, recursive so that nesting is safe */
void sys_arch_global_lock(void);
void sys_arch_global_unlock(void);

#define SYS_ARCH_DECL_PROTECT(lev)
#define SYS_ARCH_PROTECT(lev)	sys_arch_global_lock();
#define SYS_ARCH_UNPROTECT(lev)	sys_arch_global_unlock();


int sys_thread_opt_new(const char *name, void (* thread)(void *arg), void *arg, int stacksize, int prio, handle_t *id);


int sys_thread_join(handle_t id);


#endif /* PHOENIX_LWIP_SYS_ARCH_H_ */
