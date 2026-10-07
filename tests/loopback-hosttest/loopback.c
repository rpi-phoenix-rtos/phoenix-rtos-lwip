/*
 * Phoenix-RTOS --- LwIP port
 *
 * Host test: TCP over the loopback interface (127.0.0.1), through the lwIP
 * socket API, with the Raspberry Pi 4 options and the port's own sys_arch
 * locks, semaphores and mailboxes.
 *
 * On Phoenix every socket is served by its own thread of the lwip process, so
 * a program whose thread blocks in accept() while another connects is, inside
 * lwip, exactly two threads calling lwip_accept() and lwip_connect() here. A
 * poll() on one inet socket becomes lwip_select() on that socket, first with no
 * timeout, then with 20 ms ones (the kernel's POLL_INTERVAL).
 *
 * Every case runs under a watchdog: a hang fails the run instead of stalling it.
 * The last case injects one failed post to the tcpip thread's mailbox: lwIP's
 * loopback queue must still be polled afterwards.
 *
 * Copyright 2026 Phoenix Systems
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lwip/sockets.h"
#include "lwip/tcpip.h"
#include "lwip/sys.h"


#define WATCHDOG_S   10
#define ECHO_ROUNDS  2000
#define POLL_STEP_MS 20


static const char *current = "init";


static void watchdog(int sig)
{
	char buf[160];
	int n;

	(void)sig;
	n = snprintf(buf, sizeof(buf), "FAIL %s: no progress in %d s (hang)\n", current, WATCHDOG_S);
	(void)!write(2, buf, (size_t)n);
	_exit(2);
}


#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			fprintf(stderr, "FAIL %s: %s:%d: %s (errno %d)\n", current, __FILE__, __LINE__, #cond, errno); \
			exit(1); \
		} \
	} while (0)


static void tcpip_ready(void *arg)
{
	sys_sem_signal((sys_sem_t *)arg);
}


static int listener(struct sockaddr_in *addr)
{
	socklen_t len = sizeof(*addr);
	int s;

	s = lwip_socket(AF_INET, SOCK_STREAM, 0);
	CHECK(s >= 0);

	memset(addr, 0, sizeof(*addr));
	addr->sin_len = sizeof(*addr);
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = PP_HTONL(INADDR_LOOPBACK);
	CHECK(lwip_bind(s, (struct sockaddr *)addr, sizeof(*addr)) == 0);
	CHECK(lwip_listen(s, 1) == 0);
	CHECK(lwip_getsockname(s, (struct sockaddr *)addr, &len) == 0);

	return s;
}


/* poll(fd, events, timeout_ms) as the kernel's single-inet-socket path does it */
static int poll_one(int s, int wr, int timeout_ms)
{
	struct timeval tv;
	fd_set set;
	int waited = 0, step = 0, n;

	for (;;) {
		FD_ZERO(&set);
		FD_SET(s, &set);
		tv.tv_sec = 0;
		tv.tv_usec = step * 1000;
		n = lwip_select(s + 1, wr ? NULL : &set, wr ? &set : NULL, NULL, &tv);
		if (n != 0 || waited >= timeout_ms) {
			return n;
		}
		step = POLL_STEP_MS;
		waited += step;
	}
}


struct server {
	int lsock;
	int echo;
	int accepted;
};


static void *server_thread(void *arg)
{
	struct server *srv = arg;
	char buf[64];
	int c, n;

	c = lwip_accept(srv->lsock, NULL, NULL);
	CHECK(c >= 0);
	srv->accepted = 1;

	while (srv->echo) {
		n = lwip_recv(c, buf, sizeof(buf), 0);
		CHECK(n >= 0);
		if (n == 0) {
			break;
		}
		CHECK(lwip_send(c, buf, (size_t)n, 0) == n);
	}

	lwip_close(c);
	return NULL;
}


static void echo_rounds(int c, int rounds)
{
	char msg[32], buf[64];
	int i, got, n;

	memset(msg, 'x', sizeof(msg));
	for (i = 0; i < rounds; i++) {
		CHECK(lwip_send(c, msg, sizeof(msg), 0) == (int)sizeof(msg));
		for (got = 0; got < (int)sizeof(msg); got += n) {
			n = lwip_recv(c, buf, sizeof(buf), 0);
			CHECK(n > 0);
		}
	}
}


/* Blocking connect while another thread blocks in accept, then echo */
static void test_blocking_connect(void)
{
	struct server srv = { 0 };
	struct sockaddr_in addr;
	pthread_t t;
	int c;

	current = "blocking connect + accept thread";
	srv.lsock = listener(&addr);
	srv.echo = 1;
	CHECK(pthread_create(&t, NULL, server_thread, &srv) == 0);

	c = lwip_socket(AF_INET, SOCK_STREAM, 0);
	CHECK(c >= 0);
	CHECK(lwip_connect(c, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	echo_rounds(c, ECHO_ROUNDS);
	lwip_close(c);

	CHECK(pthread_join(t, NULL) == 0);
	CHECK(srv.accepted);
	lwip_close(srv.lsock);
	printf("ok   %s\n", current);
}


/* CPython's settimeout() connect: FIONBIO, connect -> EINPROGRESS, poll POLLOUT, SO_ERROR */
static void test_nonblocking_connect(void)
{
	struct server srv = { 0 };
	struct sockaddr_in addr;
	socklen_t len;
	pthread_t t;
	int c, on = 1, err;

	current = "non-blocking connect + poll, accept thread";
	srv.lsock = listener(&addr);
	srv.echo = 1;
	CHECK(pthread_create(&t, NULL, server_thread, &srv) == 0);

	c = lwip_socket(AF_INET, SOCK_STREAM, 0);
	CHECK(c >= 0);
	CHECK(lwip_ioctl(c, FIONBIO, &on) == 0);
	err = lwip_connect(c, (struct sockaddr *)&addr, sizeof(addr));
	CHECK(err == 0 || errno == EINPROGRESS);
	CHECK(poll_one(c, 1, 5000) == 1);
	len = sizeof(err);
	CHECK(lwip_getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &len) == 0);
	CHECK(err == 0);

	on = 0;
	CHECK(lwip_ioctl(c, FIONBIO, &on) == 0);
	echo_rounds(c, ECHO_ROUNDS);
	lwip_close(c);

	CHECK(pthread_join(t, NULL) == 0);
	CHECK(srv.accepted);
	lwip_close(srv.lsock);
	printf("ok   %s\n", current);
}


/* One thread: non-blocking connect, then accept (the SYN is already queued) */
static void test_single_thread(void)
{
	struct sockaddr_in addr;
	int l, c, a, on = 1, err;
	char b = 'y';

	current = "single thread non-blocking connect + accept";
	l = listener(&addr);

	c = lwip_socket(AF_INET, SOCK_STREAM, 0);
	CHECK(c >= 0);
	CHECK(lwip_ioctl(c, FIONBIO, &on) == 0);
	err = lwip_connect(c, (struct sockaddr *)&addr, sizeof(addr));
	CHECK(err == 0 || errno == EINPROGRESS);

	CHECK(poll_one(l, 0, 5000) == 1);
	a = lwip_accept(l, NULL, NULL);
	CHECK(a >= 0);
	CHECK(poll_one(c, 1, 5000) == 1);

	CHECK(lwip_send(c, &b, 1, 0) == 1);
	b = 0;
	CHECK(lwip_recv(a, &b, 1, 0) == 1 && b == 'y');

	lwip_close(a);
	lwip_close(c);
	lwip_close(l);
	printf("ok   %s\n", current);
}


/* Fault injection: the linker routes sys_mbox_trypost() calls from the lwIP
 * core (built with -Wl,--wrap=sys_mbox_trypost) through here, so a test can
 * make the next post to the tcpip thread's mailbox fail as if it were full */
err_t __real_sys_mbox_trypost(sys_mbox_t *mbox, void *msg);
static volatile int fail_next_trypost;

err_t __wrap_sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
	if (fail_next_trypost != 0) {
		fail_next_trypost = 0;
		return ERR_MEM;
	}
	return __real_sys_mbox_trypost(mbox, msg);
}


/* netif_loop_output() schedules netif_poll() only when its queue goes from
 * empty to non-empty. If that one tcpip_try_callback() fails, the queue is
 * never polled and every later packet just joins it: loopback is dead for
 * good. The connect's SYN retransmission must instead reschedule the poll. */
static void test_failed_poll_schedule(void)
{
	struct server srv = { 0 };
	struct sockaddr_in addr;
	pthread_t t;
	int c;

	current = "loopback after one failed netif_poll schedule";
	srv.lsock = listener(&addr);
	srv.echo = 1;
	CHECK(pthread_create(&t, NULL, server_thread, &srv) == 0);
	usleep(50 * 1000);

	c = lwip_socket(AF_INET, SOCK_STREAM, 0);
	CHECK(c >= 0);
	/* The SYN's tcpip_try_callback(netif_poll) is the next post */
	fail_next_trypost = 1;
	CHECK(lwip_connect(c, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	CHECK(fail_next_trypost == 0);
	echo_rounds(c, 10);
	lwip_close(c);

	CHECK(pthread_join(t, NULL) == 0);
	CHECK(srv.accepted);
	lwip_close(srv.lsock);
	printf("ok   %s\n", current);
}


/* Connect to a loopback port nobody listens on: refused, never a hang */
static void test_refused(void)
{
	struct sockaddr_in addr;
	socklen_t len;
	int l, c, on = 1, err;

	current = "non-blocking connect to a closed port";
	l = listener(&addr);
	lwip_close(l);

	c = lwip_socket(AF_INET, SOCK_STREAM, 0);
	CHECK(c >= 0);
	CHECK(lwip_ioctl(c, FIONBIO, &on) == 0);
	err = lwip_connect(c, (struct sockaddr *)&addr, sizeof(addr));
	CHECK(err == 0 || errno == EINPROGRESS || errno == ECONNREFUSED);
	if (err != 0 && errno == EINPROGRESS) {
		CHECK(poll_one(c, 1, 5000) == 1);
		len = sizeof(err);
		CHECK(lwip_getsockopt(c, SOL_SOCKET, SO_ERROR, &err, &len) == 0);
		CHECK(err != 0);
	}
	lwip_close(c);
	printf("ok   %s\n", current);
}


int main(void)
{
	sys_sem_t ready;

	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGALRM, watchdog);

	alarm(WATCHDOG_S);
	CHECK(sys_sem_new(&ready, 0) == ERR_OK);
	tcpip_init(tcpip_ready, &ready);
	sys_arch_sem_wait(&ready, 0);
	sys_sem_free(&ready);

	alarm(WATCHDOG_S);
	test_single_thread();
	alarm(WATCHDOG_S);
	test_blocking_connect();
	alarm(WATCHDOG_S);
	test_nonblocking_connect();
	alarm(WATCHDOG_S);
	test_refused();
	alarm(WATCHDOG_S);
	test_failed_poll_schedule();
	alarm(0);

	printf("PASS\n");
	return 0;
}
