/*
 * Phoenix-RTOS --- LwIP port
 *
 * Host test of the sys_arch semaphores, mailboxes and locks (see Makefile)
 *
 * Copyright 2026 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "arch/cc.h"
#include "arch/sys_arch.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


void init_lwip_global_lock(void);


static int failures;


#define CHECK(cond, ...) \
	do { \
		if (!(cond)) { \
			failures++; \
			printf("FAIL %s:%d: ", __func__, __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
	} while (0)


void bail(const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	vprintf(format, arg);
	va_end(arg);
	exit(2);
}


void errout(int err, const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	vprintf(format, arg);
	va_end(arg);
	printf(": %d\n", err);
	exit(2);
}


static long long nowMs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000L;
}


static void sleepMs(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000U, .tv_nsec = (long)(ms % 1000U) * 1000000L };

	nanosleep(&ts, NULL);
}


/* Semaphores */

static void test_semFastPath(void)
{
	sys_sem_t sem;

	memset(&sem, 0, sizeof(sem));
	CHECK(!sys_sem_valid(&sem), "zeroed semaphore reads valid");
	CHECK(sys_sem_new(&sem, 2) == ERR_OK, "sys_sem_new");
	CHECK(sys_sem_valid(&sem), "new semaphore reads invalid");
	CHECK(sys_arch_sem_wait(&sem, 0) == 0, "unit available: 0 ms");
	CHECK(sys_arch_sem_wait(&sem, 100) == 0, "unit available with timeout: 0 ms");
	CHECK(sys_arch_sem_wait(&sem, 1) == SYS_ARCH_TIMEOUT, "empty: timeout");
	sys_sem_free(&sem);
	sys_sem_set_invalid(&sem);
	CHECK(!sys_sem_valid(&sem), "set_invalid");
}


static void test_semTimeout(void)
{
	static const unsigned int timeouts[] = { 1, 10, 50, 120 };
	sys_sem_t sem;
	long long t0, dt;
	unsigned int i;
	u32_t r;

	sys_sem_new(&sem, 0);
	for (i = 0; i < sizeof(timeouts) / sizeof(timeouts[0]); i++) {
		t0 = nowMs();
		r = sys_arch_sem_wait(&sem, timeouts[i]);
		dt = nowMs() - t0;
		CHECK(r == SYS_ARCH_TIMEOUT, "timeout %u: returned %u", timeouts[i], r);
		CHECK((dt >= timeouts[i]) && (dt < timeouts[i] + 50), "timeout %u: took %lld ms", timeouts[i], dt);
	}
	sys_sem_free(&sem);
}


struct delayed {
	sys_sem_t *sem;
	sys_mbox_t *mbox;
	unsigned int ms;
};


static void *signalLater(void *arg)
{
	struct delayed *d = arg;

	sleepMs(d->ms);
	if (d->sem != NULL) {
		sys_sem_signal(d->sem);
	}
	if (d->mbox != NULL) {
		sys_mbox_post(d->mbox, (void *)(uintptr_t)0x1234);
	}
	return NULL;
}


static void test_semSignalledWait(void)
{
	sys_sem_t sem;
	struct delayed d = { .sem = &sem, .ms = 40 };
	pthread_t t;
	u32_t r;

	/* Bounded wait that is satisfied: elapsed ms, not SYS_ARCH_TIMEOUT */
	sys_sem_new(&sem, 0);
	pthread_create(&t, NULL, signalLater, &d);
	r = sys_arch_sem_wait(&sem, 2000);
	pthread_join(t, NULL);
	CHECK((r != SYS_ARCH_TIMEOUT) && (r >= 30) && (r < 200), "bounded: returned %u (expected ~40)", r);

	/* Unbounded wait */
	pthread_create(&t, NULL, signalLater, &d);
	r = sys_arch_sem_wait(&sem, 0);
	pthread_join(t, NULL);
	CHECK((r >= 30) && (r < 200), "unbounded: returned %u (expected ~40)", r);
	sys_sem_free(&sem);
}


/* Several units released while several threads wait: every waiter must get one */
#define SEM_WAITERS 6
#define SEM_ROUNDS  2000

static sys_sem_t poolSem;
static atomic_int poolTaken, poolTimeouts;


static void *poolWaiter(void *arg)
{
	int i;

	for (i = 0; i < SEM_ROUNDS; i++) {
		if (sys_arch_sem_wait(&poolSem, 5000) == SYS_ARCH_TIMEOUT) {
			atomic_fetch_add(&poolTimeouts, 1);
			return NULL;
		}
		atomic_fetch_add(&poolTaken, 1);
	}
	return NULL;
}


static void test_semCounting(void)
{
	pthread_t t[SEM_WAITERS];
	int i;

	sys_sem_new(&poolSem, 0);
	for (i = 0; i < SEM_WAITERS; i++) {
		pthread_create(&t[i], NULL, poolWaiter, NULL);
	}
	for (i = 0; i < SEM_WAITERS * SEM_ROUNDS; i++) {
		sys_sem_signal(&poolSem);
		if ((i % 64) == 0) {
			sched_yield();
		}
	}
	for (i = 0; i < SEM_WAITERS; i++) {
		pthread_join(t[i], NULL);
	}
	CHECK(atomic_load(&poolTimeouts) == 0, "%d waiters stranded with units available", atomic_load(&poolTimeouts));
	CHECK(atomic_load(&poolTaken) == SEM_WAITERS * SEM_ROUNDS, "taken %d", atomic_load(&poolTaken));
	sys_sem_free(&poolSem);
}


/* lwIP's op_completed pattern: the waiter frees the semaphore as soon as it has
 * its unit. Under ASan/TSan this catches a signaller touching it afterwards. */
static void *signalOnce(void *arg)
{
	sys_sem_signal(arg);
	return NULL;
}


static void test_semFreeAfterWake(void)
{
	sys_sem_t *sem;
	pthread_t t;
	int i;

	for (i = 0; i < 2000; i++) {
		sem = malloc(sizeof(*sem));
		sys_sem_new(sem, 0);
		pthread_create(&t, NULL, signalOnce, sem);
		CHECK(sys_arch_sem_wait(sem, 5000) != SYS_ARCH_TIMEOUT, "round %d: lost signal", i);
		sys_sem_free(sem);
		memset(sem, 0xa5, sizeof(*sem));
		free(sem);
		pthread_join(t, NULL);
	}
}


/* Mailboxes */

static void test_mboxBasic(void)
{
	sys_mbox_t mbox;
	void *msg = NULL;
	long long t0, dt;
	u32_t r;

	memset(&mbox, 0, sizeof(mbox));
	CHECK(!sys_mbox_valid(&mbox), "zeroed mbox reads valid");
	CHECK(sys_mbox_new(&mbox, 4) == ERR_OK, "sys_mbox_new");
	CHECK(sys_arch_mbox_tryfetch(&mbox, &msg) == SYS_MBOX_EMPTY, "tryfetch empty");

	/* A ring of 4 holds 3 */
	CHECK(sys_mbox_trypost(&mbox, (void *)1) == ERR_OK, "post 1");
	CHECK(sys_mbox_trypost(&mbox, (void *)2) == ERR_OK, "post 2");
	CHECK(sys_mbox_trypost(&mbox, (void *)3) == ERR_OK, "post 3");
	CHECK(sys_mbox_trypost(&mbox, (void *)4) == ERR_WOULDBLOCK, "post to full");

	CHECK((sys_arch_mbox_fetch(&mbox, &msg, 0) == 0) && (msg == (void *)1), "fetch 1 (fast path: 0 ms)");
	CHECK((sys_arch_mbox_fetch(&mbox, &msg, 10) == 0) && (msg == (void *)2), "fetch 2");
	CHECK((sys_arch_mbox_tryfetch(&mbox, &msg) == 0) && (msg == (void *)3), "tryfetch 3");

	t0 = nowMs();
	r = sys_arch_mbox_fetch(&mbox, &msg, 60);
	dt = nowMs() - t0;
	CHECK(r == SYS_ARCH_TIMEOUT, "empty fetch: returned %u", r);
	CHECK((dt >= 60) && (dt < 110), "empty fetch: took %lld ms", dt);

	sys_mbox_free(&mbox);
	sys_mbox_set_invalid(&mbox);
	CHECK(!sys_mbox_valid(&mbox), "set_invalid");
}


static void test_mboxSignalledFetch(void)
{
	sys_mbox_t mbox;
	struct delayed d = { .mbox = &mbox, .ms = 40 };
	void *msg = NULL;
	pthread_t t;
	u32_t r;

	sys_mbox_new(&mbox, 4);

	pthread_create(&t, NULL, signalLater, &d);
	r = sys_arch_mbox_fetch(&mbox, &msg, 2000);
	pthread_join(t, NULL);
	CHECK((r != SYS_ARCH_TIMEOUT) && (r >= 30) && (r < 200) && (msg == (void *)0x1234), "bounded: returned %u", r);

	msg = NULL;
	pthread_create(&t, NULL, signalLater, &d);
	r = sys_arch_mbox_fetch(&mbox, &msg, 0);
	pthread_join(t, NULL);
	CHECK((r >= 30) && (r < 200) && (msg == (void *)0x1234), "unbounded: returned %u", r);

	sys_mbox_free(&mbox);
}


static int mergeAdd(void *tail, void *msg)
{
	/* Merge only even payloads, by adding them into the tail entry */
	if (((uintptr_t)msg & 1U) != 0U) {
		return 0;
	}
	*(uintptr_t *)tail += (uintptr_t)msg;
	return 1;
}


static void test_mboxCoalesce(void)
{
	sys_mbox_t mbox;
	uintptr_t acc = 0;
	void *msg = NULL;

	sys_mbox_new(&mbox, 2);
	CHECK(sys_mbox_trypost_coalesce(&mbox, &acc, mergeAdd) == SYS_MBOX_POSTED, "first: posted");
	CHECK(sys_mbox_trypost_coalesce(&mbox, (void *)2, mergeAdd) == SYS_MBOX_COALESCED, "merged");
	CHECK(sys_mbox_trypost_coalesce(&mbox, (void *)4, mergeAdd) == SYS_MBOX_COALESCED, "merged into a full mbox");
	CHECK(sys_mbox_trypost_coalesce(&mbox, (void *)5, mergeAdd) == SYS_MBOX_FULL, "unmergeable into a full mbox");
	CHECK((sys_arch_mbox_fetch(&mbox, &msg, 0) == 0) && (msg == &acc) && (acc == 6), "fetch merged: acc=%lu", (unsigned long)acc);
	sys_mbox_free(&mbox);
}


/* Several fetchers asleep on one mbox, two posts in a row: both must wake
 * promptly. Signalling only on the empty -> non-empty transition left the second
 * asleep with a message queued, until its timeout (or forever, without one). */
static sys_mbox_t wakeMbox;
static atomic_int wakeGot;


static void *wakeFetcher(void *arg)
{
	void *msg;
	u32_t r = sys_arch_mbox_fetch(&wakeMbox, &msg, 1000);

	if ((r != SYS_ARCH_TIMEOUT) && (r < 200)) {
		atomic_fetch_add(&wakeGot, 1);
	}
	return NULL;
}


static void test_mboxTwoFetchers(void)
{
	pthread_t t[2];
	int round, i;

	sys_mbox_new(&wakeMbox, 8);
	for (round = 0; round < 10; round++) {
		atomic_store(&wakeGot, 0);
		for (i = 0; i < 2; i++) {
			pthread_create(&t[i], NULL, wakeFetcher, NULL);
		}
		sleepMs(10); /* both asleep */
		sys_mbox_post(&wakeMbox, (void *)1);
		sys_mbox_post(&wakeMbox, (void *)2);
		for (i = 0; i < 2; i++) {
			pthread_join(t[i], NULL);
		}
		CHECK(atomic_load(&wakeGot) == 2, "round %d: %d of 2 fetchers woke promptly", round, atomic_load(&wakeGot));
	}
	sys_mbox_free(&wakeMbox);
}


/* Producers block on a full ring (sys_mbox_post), consumers drain it with short
 * timeouts: every message is delivered exactly once */
#define MB_PRODUCERS 4
#define MB_CONSUMERS 3
#define MB_PER_PROD  20000
#define MB_SIZE      8

static sys_mbox_t streamMbox;
static atomic_long streamSum, streamCount;
static atomic_int streamDone;


static void *streamProducer(void *arg)
{
	uintptr_t base = (uintptr_t)arg * MB_PER_PROD;
	uintptr_t i;

	for (i = 1; i <= MB_PER_PROD; i++) {
		sys_mbox_post(&streamMbox, (void *)(base + i));
	}
	return NULL;
}


static void *streamConsumer(void *arg)
{
	void *msg;

	for (;;) {
		if (sys_arch_mbox_fetch(&streamMbox, &msg, 3) == SYS_ARCH_TIMEOUT) {
			if (atomic_load(&streamDone) != 0) {
				return NULL;
			}
			continue;
		}
		atomic_fetch_add(&streamSum, (long)(uintptr_t)msg);
		atomic_fetch_add(&streamCount, 1);
	}
}


static void test_mboxStream(void)
{
	pthread_t p[MB_PRODUCERS], c[MB_CONSUMERS];
	long expectSum = 0, n = (long)MB_PRODUCERS * MB_PER_PROD;
	int i;

	sys_mbox_new(&streamMbox, MB_SIZE);
	for (i = 0; i < MB_CONSUMERS; i++) {
		pthread_create(&c[i], NULL, streamConsumer, NULL);
	}
	for (i = 0; i < MB_PRODUCERS; i++) {
		pthread_create(&p[i], NULL, streamProducer, (void *)(uintptr_t)i);
	}
	for (i = 0; i < MB_PRODUCERS; i++) {
		pthread_join(p[i], NULL);
	}
	while (atomic_load(&streamCount) < n) {
		sleepMs(1);
	}
	atomic_store(&streamDone, 1);
	for (i = 0; i < MB_CONSUMERS; i++) {
		pthread_join(c[i], NULL);
	}

	expectSum = n * (n + 1) / 2;
	CHECK(atomic_load(&streamCount) == n, "count %ld of %ld", atomic_load(&streamCount), n);
	CHECK(atomic_load(&streamSum) == expectSum, "sum %ld, expected %ld", atomic_load(&streamSum), expectSum);
	sys_mbox_free(&streamMbox);
}


/* Locks */

#define LOCK_THREADS 4
#define LOCK_ITERS   200000

static sys_mutex_t coreLock;
static long coreCounter, protCounter;


static void *lockWorker(void *arg)
{
	int i;

	for (i = 0; i < LOCK_ITERS; i++) {
		sys_mutex_lock(&coreLock);
		coreCounter++;
		sys_mutex_unlock(&coreLock);

		/* Nested, as a PROTECT region calling into another one */
		SYS_ARCH_PROTECT(lev);
		SYS_ARCH_PROTECT(lev);
		protCounter++;
		SYS_ARCH_UNPROTECT(lev);
		protCounter++;
		SYS_ARCH_UNPROTECT(lev);
	}
	return NULL;
}


static void test_locks(void)
{
	pthread_t t[LOCK_THREADS];
	int i;

	memset(&coreLock, 0, sizeof(coreLock));
	CHECK(!sys_mutex_valid(&coreLock), "zeroed mutex reads valid");
	CHECK(sys_mutex_new(&coreLock) == ERR_OK, "sys_mutex_new");
	CHECK(sys_mutex_valid(&coreLock), "new mutex reads invalid");

	for (i = 0; i < LOCK_THREADS; i++) {
		pthread_create(&t[i], NULL, lockWorker, NULL);
	}
	for (i = 0; i < LOCK_THREADS; i++) {
		pthread_join(t[i], NULL);
	}
	CHECK(coreCounter == (long)LOCK_THREADS * LOCK_ITERS, "mutex counter %ld", coreCounter);
	CHECK(protCounter == 2L * LOCK_THREADS * LOCK_ITERS, "protect counter %ld", protCounter);
	sys_mutex_free(&coreLock);
}


static atomic_int protEntered;


static void *protectOther(void *arg)
{
	SYS_ARCH_PROTECT(lev);
	atomic_store(&protEntered, 1);
	SYS_ARCH_UNPROTECT(lev);
	return NULL;
}


static void test_protectExcludes(void)
{
	pthread_t t;

	/* Held twice by us: another thread stays out until the outer unprotect */
	SYS_ARCH_PROTECT(lev);
	SYS_ARCH_PROTECT(lev);
	pthread_create(&t, NULL, protectOther, NULL);
	sleepMs(20);
	SYS_ARCH_UNPROTECT(lev);
	sleepMs(20);
	CHECK(atomic_load(&protEntered) == 0, "entered while held at depth 1");
	SYS_ARCH_UNPROTECT(lev);
	pthread_join(t, NULL);
	CHECK(atomic_load(&protEntered) == 1, "never entered");
}


int main(void)
{
	init_lwip_global_lock();

	test_semFastPath();
	test_semTimeout();
	test_semSignalledWait();
	test_semCounting();
	test_semFreeAfterWake();
	test_mboxBasic();
	test_mboxSignalledFetch();
	test_mboxCoalesce();
	test_mboxTwoFetchers();
	test_mboxStream();
	test_locks();
	test_protectExcludes();

	printf("%s: %d failure(s)\n", (failures == 0) ? "PASS" : "FAIL", failures);
	return (failures == 0) ? 0 : 1;
}
