#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>


char *header =	"HTTP/1.1 200 OK\r\n" \
				"Cache-Control: no-cache\r\n" \
				"Server: net-test\r\n" \
				"Connection: Keep-Alive\r\n" \
				"Content-Type: text/html\r\n" \
				"\r\n";

static int v = 0;

#define ntmsg(verbose, fmt, ...)		\
	do {								\
		if (verbose <= v)				\
			printf(fmt, ##__VA_ARGS__);	\
	} while (0)

void print_help(void)
{
	printf("Usage: net-test -v [verbose] -b (nonblock) -w [write-size] -c [count] -p [file-path]\n");
	printf("       net-test -C <host> [-t port] [-c count] [-P] [-g gap-us]   (ping-pong RTT client)\n");
	printf("         -C host : run TCP ping-pong latency probe against a host echo server\n");
	printf("         -P      : use poll()+read() instead of blocking read() (matches libnfs)\n");
	printf("         -t port : echo server port (default 7777)\n");
	printf("         -g us   : idle gap between round-trips in us (default 1000) so the socket\n");
	printf("                   goes idle before each recv (reproduces the idle->wake stall)\n");
}


/* TCP ping-pong RTT probe. Sends 4 bytes, waits for the 4-byte echo, times the
 * round-trip. The recv wait (blocking read, or poll()+read with -P) is exactly the
 * path where a missed socket-readiness wakeup stalls: if data arrives but the wait
 * isn't woken, the RTT spikes to ~the peer/timer bound (~200ms). Prints min/avg/max
 * + a >10ms spike count + the worst few, which reproduces the gigabit NFS stall in
 * seconds instead of a 120s mount. */
static int run_pingpong(const char *host, int port, int cnt, int usepoll, int gap_us)
{
	int fd, i, one = 1;
	struct sockaddr_in sa = { 0 };
	char msg[8];
	long long minus = 1000000000LL, maxus = 0, sumus = 0;
	int spikes = 0, ok = 0;
	long long worst[3] = { 0, 0, 0 };

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		printf("PINGPONG: socket error\n");
		return -1;
	}
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
		printf("PINGPONG: bad host %s\n", host);
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("PINGPONG: connect to %s:%d failed\n", host, port);
		close(fd);
		return -1;
	}
	/* Disable Nagle so a small ping is sent immediately (clean RTT, not batched). */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	printf("PINGPONG: connected to %s:%d mode=%s count=%d gap=%dus\n",
		host, port, usepoll ? "poll" : "block", cnt, gap_us);

	for (i = 0; i < cnt; i++) {
		struct timespec t0, t1;
		int r;

		if (gap_us > 0)
			usleep(gap_us);   /* let the socket go idle before this round-trip */

		clock_gettime(CLOCK_MONOTONIC, &t0);
		memcpy(msg, "ping", 4);
		if (write(fd, msg, 4) != 4) {
			printf("PINGPONG: write failed at %d\n", i);
			break;
		}
		if (usepoll) {
			struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
			int pr = poll(&pfd, 1, 3000);
			if (pr <= 0) {
				printf("PINGPONG: poll timeout/err (%d) at %d\n", pr, i);
				break;
			}
		}
		r = read(fd, msg, 4);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		if (r <= 0) {
			printf("PINGPONG: read failed (%d) at %d\n", r, i);
			break;
		}

		long long us = (t1.tv_sec - t0.tv_sec) * 1000000LL +
			(t1.tv_nsec - t0.tv_nsec) / 1000;
		ok++;
		sumus += us;
		if (us < minus)
			minus = us;
		if (us > maxus)
			maxus = us;
		if (us > 10000) {   /* >10ms = a stall spike */
			spikes++;
			if (us > worst[0]) { worst[2] = worst[1]; worst[1] = worst[0]; worst[0] = us; }
		}
	}

	printf("PINGPONG RESULT mode=%s n=%d min=%lldus avg=%lldus max=%lldus spikes(>10ms)=%d "
		"worst=%lld/%lld/%lld us\n",
		usepoll ? "poll" : "block", ok, minus, ok ? sumus / ok : 0, maxus,
		spikes, worst[0], worst[1], worst[2]);
	close(fd);
	return 0;
}


int main(int argc, char **argv)
{
	struct sockaddr_in saddr = { 0 };
	char *buffer, *path = NULL;
	int ret, srv, fd, fd2, i, n, c, cnt = 100;
	int nonblock = 0, writesz = 4096;
	char *client_host = NULL;
	int port = 7777, usepoll = 0, gap_us = 1000;

	while ((c = getopt(argc, argv, "v:bw:c:p:hC:Pt:g:")) != -1) {
		switch (c) {

		case 'b':
			nonblock = 1;
			break;
		case 'w':
			writesz = atoi(optarg);
			break;
		case 'c':
			cnt = atoi(optarg);
			break;
		case 'p':
			path = optarg;
			break;
		case 'v':
			v = atoi(optarg);
			break;
		case 'C':
			client_host = optarg;
			break;
		case 'P':
			usepoll = 1;
			break;
		case 't':
			port = atoi(optarg);
			break;
		case 'g':
			gap_us = atoi(optarg);
			break;
		case 'h':
			print_help();
			break;
		}
	}

	/* Client ping-pong RTT probe mode (-C host): reproduces the socket-readiness
	 * wakeup stall directly, without NFS. */
	if (client_host != NULL) {
		return run_pingpong(client_host, port, cnt, usepoll, gap_us);
	}

	buffer = malloc(writesz);

	ntmsg(1, "-----------------------\n");	
	ntmsg(1, "test options:\n\twrite size %d\n\twrite count %d\n", writesz, cnt);
	if (nonblock)
		ntmsg(1, "\tnonblocking writes\n");
	if (path != NULL)
		ntmsg(1, "\tfile path %s\n", path);
	ntmsg(1, "-----------------------\n");	

	srv = socket(AF_INET, SOCK_STREAM, 0);
	if (srv == -1) {
		printf("socket error\n");
		return 0;
	}

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(80);
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((ret = bind(srv, (struct sockaddr *) &saddr, sizeof(saddr))) < 0) {
		printf("bind error: %s\n", strerror(ret));
		return 0;
	}

	ret = 1;
	setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(int));

	if (listen(srv, 50) < 0) {
		printf("listen error\n");
		return 0;
	}

	ntmsg(2, "fill buffer\n");

	for (i = 0; i < writesz; i++)
		buffer[i] = i % 256;

	ntmsg(2, "wait for connection\n");
	socklen_t saddrsz = sizeof(saddr);

	if ((fd = accept4(srv, (struct sockaddr *)&saddr, &saddrsz, nonblock ? SOCK_NONBLOCK : 0)) < 0) {
		printf("accept error\n");
		goto error;
	}
	ntmsg(2, "connection accepted\n");

	write(fd, header, strlen(header));

	if (path != NULL) {
		ntmsg(2, "opening file %s\n", path);
		fd2 = open(path, O_RDONLY);
		if (fd2 > 0) {
			for (i = 0; i < cnt; i++) {
				if ((n = read(fd2, buffer, writesz)) <= 0)
					break;
				n = write(fd, buffer, n);
				if (nonblock && n < writesz) {
					ntmsg(2, "partial write %d (should be %d)\n", n, writesz);
					while (n < writesz)
						n += write(fd, buffer + n, writesz - n);
				}
			}

			close(fd2);
		}
	} else {
		for (i = 0; i < cnt; i++) {
			if ((n = write(fd, buffer, writesz)) <= 0)
				break;

			if (nonblock && n < writesz) {
				ntmsg(2, "partial write %d (should be %d)\n", n, writesz);
				while (n < writesz)
					n += write(fd, buffer + n, writesz - n);
			}
		}
	}
	close(fd);

error:
	close(srv);
	free(buffer);

	return 0;
}
