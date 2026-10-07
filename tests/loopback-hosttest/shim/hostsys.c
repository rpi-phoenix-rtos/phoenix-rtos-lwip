/* Host stand-ins for the port's Phoenix-specific sys_arch pieces: threads
 * (port/threads.c uses beginthreadex), the clock and the diagnostics */
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lwip/sys.h"

struct thread_start {
	void (*fn)(void *);
	void *arg;
};

static void *thread_main(void *arg)
{
	struct thread_start ts = *(struct thread_start *)arg;

	free(arg);
	ts.fn(ts.arg);
	return NULL;
}

int sys_thread_opt_new(const char *name, void (*thread)(void *arg), void *arg, int stacksize, int prio, handle_t *id)
{
	struct thread_start *ts = malloc(sizeof(*ts));
	pthread_t t;

	if (ts == NULL)
		return -1;
	ts->fn = thread;
	ts->arg = arg;
	if (pthread_create(&t, NULL, thread_main, ts) != 0) {
		free(ts);
		return -1;
	}
	pthread_detach(t);
	if (id != NULL)
		*id = 0;
	return 0;
}

sys_thread_t sys_thread_new(const char *name, void (*thread)(void *arg), void *arg, int stacksize, int prio)
{
	if (sys_thread_opt_new(name, thread, arg, stacksize, prio, NULL) != 0)
		bail("thread %s\n", name);
	return 0;
}

u32_t sys_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (u32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

void sys_init(void)
{
	void init_lwip_global_lock(void);

	init_lwip_global_lock();
}

void bail(const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	vfprintf(stderr, format, arg);
	va_end(arg);
	abort();
}

void errout(int err, const char *format, ...)
{
	va_list arg;

	va_start(arg, format);
	vfprintf(stderr, format, arg);
	va_end(arg);
	fprintf(stderr, ": %d\n", err);
	exit(1);
}

/* Referenced by tcpip_callbackmsg_trycallback_fromisr(), which nothing calls;
 * the port leaves it to the linker's section garbage collection */
err_t sys_mbox_trypost_fromisr(sys_mbox_t *mbox, void *msg)
{
	return sys_mbox_trypost(mbox, msg);
}
