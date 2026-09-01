/*
 * Phoenix-RTOS --- LwIP port
 *
 * BCM43455 WiFi netif (Pi 4 / Pi 400, frames bridged to the rpi4-wifi daemon)
 *
 * Copyright 2026 Phoenix Systems
 *
 * %LICENSE%
 *
 * Unlike bcm-genet.c this driver owns no hardware. The whole SDIO/SDPCM stack
 * for the BCM43455 lives in the rpi4-wifi daemon, which must stay the single
 * owner of the bus (control, event and data frames share one F2 FIFO, so two
 * drainers would steal each other's frames). The daemon therefore exposes two
 * device files and this driver is the lwIP end of that seam:
 *
 *   /dev/wifidata  raw 802.3 frames
 *                    write(fd, frame, len)  transmits; returns len, or <0
 *                    read(fd, buf, cap)     >0 = length of ONE received frame,
 *                                           0 = nothing queued, <0 = error.
 *                                           NEVER blocks (the daemon has a
 *                                           single message thread).
 *   /dev/wifi      text commands: write the command, lseek() back to 0, then
 *                  read() the text reply (the write advances the offset).
 *                    "mac"                   -> reply has a "MAC aa:bb:.." line
 *                    "joinwpa <ssid> <psk>"  -> associate + WPA2 4-way key,
 *                                               NO DHCP; 20-40 s; reply has
 *                                               "JOINWPA ok|fail ..." + "MAC ..."
 *
 * Consequences for the netif lifecycle:
 *
 *   - The daemon is started from the shell, i.e. AFTER lwIP is already running,
 *     so at init() time both device files are normally still absent. init()
 *     must not fail on that: it brings the netif up with the link DOWN and
 *     leaves all device I/O to a join thread that retries the opens forever.
 *   - The join itself takes 20-40 s and init() runs on the tcpip thread, so the
 *     join must not happen inline either -- same join thread.
 *   - DHCP is this driver's job (the daemon's `joinwpa` deliberately skips it),
 *     exactly as in bcm-genet.c: on the first link-up we kick dhcp_start() from
 *     a tcpip_callback.
 *
 * Config string (everything after the first ':' of the boot token):
 *
 *   wifi43455:<ssid>:<psk>   credentials inline (psk is the whole remainder,
 *                            so it may itself contain ':')
 *   wifi43455                credentials from /etc/wifi.conf ("ssid=" / "psk="
 *                            key=value lines, '#' comments) so the boot config
 *                            carries no secret.
 */
#include "netif-driver.h"

#include "lwip/dhcp.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/snmp.h"
#include "lwip/tcpip.h"

#include <sys/threads.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define WIFI_DATA_DEV "/dev/wifidata"
#define WIFI_CTL_DEV  "/dev/wifi"
#define WIFI_CONF     "/etc/wifi.conf"

/* TX bounds are the daemon's accepted write() range (frame >= Ethernet header,
 * <= F2_FRAME_MAX - SDPCM/BDC headers). */
#define WIFI_TX_MIN 14u
#define WIFI_TX_MAX 2032u

/* RX staging buffer is the daemon's full F2_FRAME_MAX, NOT WIFI_TX_MAX: a read
 * whose frame does not fit the caller's buffer is answered with -EMSGSIZE and
 * the frame is lost, so the cap must not be the (smaller) TX limit. */
#define WIFI_RX_BUF 2048u

#define WIFI_RESP_MAX 512u /* text reply from /dev/wifi ("mac"/"joinwpa" are short) */

/* /dev/wifidata never blocks, so an idle RX thread polls. 1.5 ms costs ~660
 * wakeups/s at idle and adds at most that much latency to a frame; the radio
 * ceiling over SDIO is a few MB/s, far below what a tighter poll would buy. */
/* Idle RX poll cadence. This is the dominant throughput term, not the radio:
 * TCP cannot advance its window faster than ACKs are picked up, so an idle
 * sleep of N us puts a ceiling near one frame per N us. Measured on hardware:
 * 1500 us gave 0.58 MB/s = 402 frames/s = 2.49 ms/frame, i.e. almost exactly
 * the poll interval plus processing. The real fix is an event-driven read on
 * the daemon side; until then keep this small. */
#define WIFI_RX_IDLE_US   200u
#define WIFI_RX_ERR_US    20000u /* back off a little on a read error */
#define WIFI_DEV_RETRY_S  2u     /* device files appear when rpi4-wifi starts */
#define WIFI_JOIN_RETRY_S 10u
#define WIFI_JOIN_TRIES   3u
/* /etc/wifi.conf is only consulted once the daemon's device files exist, which
 * proves the filesystem holding both is mounted -- a few tries cover a slow
 * first read, not a pending root takeover. */
#define WIFI_CONF_TRIES   5u


typedef struct {
	struct netif *netif;

	int data_fd; /* /dev/wifidata -- raw frames */
	int ctl_fd;  /* /dev/wifi     -- text commands */

	char ssid[33]; /* 32 + NUL, per IEEE 802.11 */
	char psk[65];  /* 64 + NUL, per WPA2-PSK */

	uint8_t mac[6];
	bool mac_valid;
	bool joined;

	/* Written by the join thread, read by linkoutput/media/stats on other
	 * threads. Plain int: a torn read is impossible on this target and the
	 * only transition is 0 -> 1 (a stale 0 just delays the first TX). */
	volatile int link_up;
	int dhcp_started;

	handle_t tx_lock; /* lwIP may call linkoutput from several threads */
	uint8_t tx_buf[WIFI_TX_MAX];
	uint8_t rx_buf[WIFI_RX_BUF];
	char resp[WIFI_RESP_MAX];

	unsigned long rx_ok;
	unsigned long rx_err;
	unsigned long rx_toobig;
	unsigned long tx_ok;
	unsigned long tx_err;

	/* 16 KB: the RX thread runs netif->input() -> tcpip mailbox post; sized
	 * like genet's drain thread (these stacks have no guard page). */
	uint32_t rx_stack[4096] __attribute__((aligned(16)));
	/* 8 KB: the join thread only does device I/O + snprintf/printf; its text
	 * buffers live in this struct rather than on the stack. */
	uint32_t join_stack[2048] __attribute__((aligned(16)));
} wifi_state_t;


#define wifi_printf(fmt, ...) printf("lwip: wifi43455: " fmt "\n", ##__VA_ARGS__)


/* --- /dev/wifi text-command helper ------------------------------- */

/* Run one command and collect its text reply into state->resp (NUL-terminated).
 * The write advances the fd offset, so seek back to 0 before reading -- same
 * sequence as the `wifi` control client. Returns 0 on success. */
static int wifi_command(wifi_state_t *state, const char *cmd)
{
	size_t len = strlen(cmd);
	size_t total = 0;
	ssize_t n;

	state->resp[0] = '\0';

	if (write(state->ctl_fd, cmd, len) != (ssize_t)len) {
		return -EIO;
	}
	if (lseek(state->ctl_fd, 0, SEEK_SET) < 0) {
		return -EIO;
	}

	while (total < sizeof(state->resp) - 1u) {
		n = read(state->ctl_fd, state->resp + total, sizeof(state->resp) - 1u - total);
		if (n <= 0) {
			break;
		}
		total += (size_t)n;
	}
	state->resp[total] = '\0';

	return (total > 0u) ? 0 : -EIO;
}


/* Pick the "MAC aa:bb:cc:dd:ee:ff" line out of a reply. Returns 0 on success;
 * "MAC unavailable" and an all-zero address are rejected. */
static int wifi_parseMac(const char *reply, uint8_t out[6])
{
	const char *line = reply;
	unsigned v[6];
	int i;

	while (*line != '\0') {
		if ((strncmp(line, "MAC ", 4) == 0) &&
			(sscanf(line + 4, "%x:%x:%x:%x:%x:%x",
				&v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6)) {
			unsigned any = 0u;
			for (i = 0; i < 6; ++i) {
				if (v[i] > 0xffu) {
					break;
				}
				any |= v[i];
			}
			if ((i == 6) && (any != 0u)) {
				for (i = 0; i < 6; ++i) {
					out[i] = (uint8_t)v[i];
				}
				return 0;
			}
		}

		line = strchr(line, '\n');
		if (line == NULL) {
			break;
		}
		line++;
	}

	return -ENODEV;
}


/* --- credentials -------------------------------------------------- */

/* cfg is everything after the first ':' of the boot token: "<ssid>:<psk>",
 * where the psk is the whole remainder and may contain ':'. An EMPTY cfg is not
 * an error -- it selects the /etc/wifi.conf path, which keeps secrets out of
 * the boot config. A cfg that names an ssid but no psk is a real mistake and
 * fails the init, since silently reading a different ssid's key from the file
 * would be worse than a loud failure. */
static int wifi_parseCfg(wifi_state_t *state, const char *cfg)
{
	const char *sep;
	size_t ssid_len;

	if ((cfg == NULL) || (*cfg == '\0')) {
		return 0;
	}

	sep = strchr(cfg, ':');
	if ((sep == NULL) || (sep == cfg) || (sep[1] == '\0')) {
		wifi_printf("bad cfg \"%s\" (want <ssid>:<psk>, or nothing for %s)", cfg, WIFI_CONF);
		return -EINVAL;
	}

	ssid_len = (size_t)(sep - cfg);
	if ((ssid_len >= sizeof(state->ssid)) || (strlen(sep + 1) >= sizeof(state->psk))) {
		wifi_printf("bad cfg: ssid or psk too long");
		return -EINVAL;
	}

	memcpy(state->ssid, cfg, ssid_len);
	state->ssid[ssid_len] = '\0';
	strcpy(state->psk, sep + 1);

	return 0;
}


/* Trim leading and trailing blanks (and the newline) in place. */
static char *wifi_trim(char *s)
{
	char *end;

	while ((*s == ' ') || (*s == '\t')) {
		s++;
	}
	for (end = s + strlen(s); (end > s) && ((end[-1] == '\n') || (end[-1] == '\r') ||
			(end[-1] == ' ') || (end[-1] == '\t')); end--) {
		end[-1] = '\0';
	}

	return s;
}


/* /etc/wifi.conf: INI-lite "key=value" per line, '#' comments, blanks trimmed.
 * Matches the tolerance of the `wifi up` client's parser. Unknown keys are
 * ignored. Returns 0 if BOTH ssid and psk were found. */
static int wifi_readConf(wifi_state_t *state)
{
	FILE *f = fopen(WIFI_CONF, "r");
	char line[192];
	char *key, *val, *eq;

	if (f == NULL) {
		return -ENOENT;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		eq = strchr(line, '=');
		if (eq == NULL) {
			continue;
		}
		*eq = '\0';
		key = wifi_trim(line);
		if ((*key == '#') || (*key == '\0')) {
			continue;
		}
		val = wifi_trim(eq + 1);

		if ((strcmp(key, "ssid") == 0) && (strlen(val) < sizeof(state->ssid))) {
			strcpy(state->ssid, val);
		}
		else if ((strcmp(key, "psk") == 0) && (strlen(val) < sizeof(state->psk))) {
			strcpy(state->psk, val);
		}
	}
	fclose(f);

	return ((state->ssid[0] != '\0') && (state->psk[0] != '\0')) ? 0 : -ENOENT;
}


/* --- link up + DHCP ---------------------------------------------- */

static void wifi_dhcpStartCb(void *arg)
{
	struct netif *netif = arg;
	err_t err;

	/* Do NOT take the default route away from a link that already has it: on
	 * this board genet is the primary interface and comes up first. Traffic to
	 * the WiFi subnet still selects this netif by address, so the only thing
	 * grabbing the default would change is silently pushing every off-subnet
	 * packet over WiFi. */
	if (netif_default == NULL) {
		netif_set_default(netif);
	}

	/* Bring the netif administratively UP. lwIP's dhcp_start() refuses with
	 * ERR_ARG (-16) unless netif_is_up(), and unlike genet we never got
	 * NETIF_FLAG_UP for free: netif_dev_init() only applies that default to a
	 * hardcoded list of driver names ("enet"/"rtl"/"greth"/"genet"), which a
	 * new name cannot match. Observed on hardware as `dhcp_start: -16` right
	 * after a successful join. */
	netif_set_up(netif);

	err = dhcp_start(netif);
	wifi_printf("dhcp_start: %d (0=ok); netif waits for OFFER", (int)err);

	/* Gratuitous ARP right after dhcp_start is a no-op (the netif IP is still
	 * 0.0.0.0) and lwIP handles that gracefully; the first useful ARP fires
	 * from dhcp.c when the lease completes and netif_set_addr runs. */
	(void)etharp_gratuitous(netif);
}


static void wifi_linkUp(wifi_state_t *state)
{
	struct netif *netif = state->netif;

	/* lwIP reads netif->hwaddr when it builds the ARP and DHCP frames, so the
	 * address must be in place BEFORE the link comes up -- the join thread
	 * learns it from the daemon and only then calls this. */
	memcpy(netif->hwaddr, state->mac, 6);
	netif->hwaddr_len = 6;

	netif_set_link_up(netif);

	/* dhcp_start touches lwIP's timer + UDP state, which needs the tcpip-thread
	 * context under LWIP_TCPIP_CORE_LOCKING: calling it from this thread
	 * "succeeds" but the DISCOVER never reaches the wire because the DHCP timer
	 * never starts. Schedule it via tcpip_callback (see bcm-genet.c). */
	if (state->dhcp_started == 0) {
		err_t err = tcpip_callback(wifi_dhcpStartCb, netif);
		wifi_printf("tcpip_callback(dhcp_start): %d", (int)err);
		state->dhcp_started = 1;
	}
}


/* --- join thread -------------------------------------------------- */

/* Resolve credentials: inline cfg wins, else /etc/wifi.conf. Returns 0 once
 * both an ssid and a psk are known. */
static int wifi_resolveCreds(wifi_state_t *state)
{
	unsigned try;

	if ((state->ssid[0] != '\0') && (state->psk[0] != '\0')) {
		return 0;
	}

	for (try = 0; try < WIFI_CONF_TRIES; ++try) {
		if (wifi_readConf(state) == 0) {
			return 0;
		}
		sleep(WIFI_DEV_RETRY_S);
	}

	/* Not an error worth failing the netif over: the interface simply stays
	 * down until someone adds credentials and restarts. Logged once. */
	wifi_printf("no credentials (boot cfg is empty and %s has no ssid=/psk=); link stays down",
		WIFI_CONF);

	return -ENOENT;
}


/* Open both device files. The rpi4-wifi daemon is started from the shell, so
 * this normally fails for the first few seconds (or minutes) of uptime. */
static int wifi_openDevs(wifi_state_t *state)
{
	int data_fd, ctl_fd;

	data_fd = open(WIFI_DATA_DEV, O_RDWR);
	if (data_fd < 0) {
		return -ENOENT;
	}

	ctl_fd = open(WIFI_CTL_DEV, O_RDWR);
	if (ctl_fd < 0) {
		close(data_fd);
		return -ENOENT;
	}

	/* Publish data_fd only once BOTH opens succeeded: the RX thread polls that
	 * field, and a half-open state would have it read from a descriptor this
	 * thread is about to close. */
	state->ctl_fd = ctl_fd;
	state->data_fd = data_fd;

	return 0;
}


static void wifi_joinThread(void *arg)
{
	wifi_state_t *state = arg;
	bool waiting_logged = false;
	unsigned try;

	/* Wait for the daemon indefinitely but cheaply -- there is no sensible
	 * "give up" point: the operator may start rpi4-wifi at any time. */
	while (wifi_openDevs(state) < 0) {
		if (!waiting_logged) {
			wifi_printf("waiting for %s (start the rpi4-wifi daemon)", WIFI_DATA_DEV);
			waiting_logged = true;
		}
		sleep(WIFI_DEV_RETRY_S);
	}
	wifi_printf("%s + %s open", WIFI_DATA_DEV, WIFI_CTL_DEV);

	/* Credentials are resolved only AFTER the device files appear, never before:
	 * on netboot lwip starts on a dummyfs "/" and the real root (holding both
	 * the rpi4-wifi binary and /etc/wifi.conf) is taken over later. The daemon
	 * being up therefore proves the filesystem carrying the conf is mounted, so
	 * a bounded retry here is enough. */
	if (wifi_resolveCreds(state) < 0) {
		endthread();
	}

	/* The MAC is also echoed by the joinwpa reply, so a failure here is not
	 * fatal yet -- but the link must not come up without it (see wifi_linkUp). */
	if ((wifi_command(state, "mac") == 0) && (wifi_parseMac(state->resp, state->mac) == 0)) {
		state->mac_valid = true;
		wifi_printf("MAC %02x:%02x:%02x:%02x:%02x:%02x",
			state->mac[0], state->mac[1], state->mac[2],
			state->mac[3], state->mac[4], state->mac[5]);
	}

	for (try = 1; try <= WIFI_JOIN_TRIES; ++try) {
		char cmd[128];
		int n = snprintf(cmd, sizeof(cmd), "joinwpa %s %s", state->ssid, state->psk);

		if ((n < 0) || (n >= (int)sizeof(cmd))) {
			wifi_printf("ssid/psk too long for a joinwpa command");
			endthread();
		}

		wifi_printf("joining \"%s\" (WPA2 associate + 4-way key, 20-40s)", state->ssid);
		if (wifi_command(state, cmd) < 0) {
			wifi_printf("joinwpa: no reply from %s (attempt %u/%u)",
				WIFI_CTL_DEV, try, WIFI_JOIN_TRIES);
		}
		else if (strstr(state->resp, "JOINWPA ok") != NULL) {
			state->joined = true;
			if (!state->mac_valid && (wifi_parseMac(state->resp, state->mac) == 0)) {
				state->mac_valid = true;
			}
			if (!state->mac_valid) {
				wifi_printf("joined \"%s\" but the station MAC is unknown; link stays down",
					state->ssid);
				endthread();
			}
			wifi_printf("joined \"%s\"; bringing link up", state->ssid);
			state->link_up = 1;
			wifi_linkUp(state);
			endthread();
		}
		else {
			/* The reply's first line carries setssid=/psksup=/link= detail. */
			wifi_printf("joinwpa failed (attempt %u/%u): %s", try, WIFI_JOIN_TRIES, state->resp);
		}

		if (try < WIFI_JOIN_TRIES) {
			sleep(WIFI_JOIN_RETRY_S);
		}
	}

	/* Give up quietly: the netif stays registered with the link down, so a
	 * later `wifi netup` from the shell still works over the daemon. */
	wifi_printf("giving up on \"%s\" after %u attempts; link stays down",
		state->ssid, WIFI_JOIN_TRIES);
	endthread();
}


/* --- RX thread ---------------------------------------------------- */

/* Wrap one received frame in a pbuf and hand it to lwIP. */
static void wifi_deliverRx(wifi_state_t *state, size_t len)
{
	struct netif *netif = state->netif;
	struct pbuf *p;

	/* lwIP is built with ETH_PAD_SIZE=2: allocate the pad, zero it, and place
	 * the frame behind it so the Ethernet header lands 2-byte-offset (the
	 * alignment the IP header needs). Same shape as bcm-genet.c's copy path. */
	p = pbuf_alloc(PBUF_RAW, (uint16_t)(len + ETH_PAD_SIZE), PBUF_RAM);
	if (p == NULL) {
		state->rx_err++;
		return;
	}

	((uint8_t *)p->payload)[0] = 0;
	((uint8_t *)p->payload)[1] = 0;

	if (pbuf_take_at(p, state->rx_buf, (uint16_t)len, ETH_PAD_SIZE) != ERR_OK) {
		pbuf_free(p);
		state->rx_err++;
		return;
	}

	/* netif->input is the framework's tcpip_input; on anything but ERR_OK the
	 * pbuf was NOT consumed and is ours to free. */
	if (netif->input(p, netif) != ERR_OK) {
		pbuf_free(p);
		state->rx_err++;
		return;
	}

	state->rx_ok++;
}


static void wifi_rxThread(void *arg)
{
	wifi_state_t *state = arg;
	ssize_t n;

	for (;;) {
		/* The join thread owns the opens; until they land there is nothing to
		 * poll. No lock is held across read(): during the 20-40 s join the
		 * daemon's single message thread is busy and this read queues behind
		 * it, which must not stall TX or the join. */
		if (state->data_fd < 0) {
			sleep(WIFI_DEV_RETRY_S);
			continue;
		}

		n = read(state->data_fd, state->rx_buf, sizeof(state->rx_buf));
		if (n > 0) {
			wifi_deliverRx(state, (size_t)n);
		}
		else if (n == 0) {
			usleep(WIFI_RX_IDLE_US); /* nothing queued -- read() never blocks */
		}
		else {
			if (errno == EMSGSIZE) {
				state->rx_toobig++; /* frame longer than WIFI_RX_BUF; dropped */
			}
			else {
				state->rx_err++;
			}
			usleep(WIFI_RX_ERR_US);
		}
	}
}


/* --- linkoutput / media / stats ---------------------------------- */

static err_t wifi_linkOutput(struct netif *netif, struct pbuf *p)
{
	wifi_state_t *state = netif->state;
	uint16_t len;

	if (state->link_up == 0) {
		return ERR_IF;
	}

	/* With ETH_PAD_SIZE=2 lwIP leaves the 2-byte head pad ON the pbuf handed to
	 * linkoutput, so the wire length is tot_len minus the pad and the copy must
	 * start past it -- otherwise the frame would begin with two zero bytes in
	 * front of the destination MAC. */
	if ((p->tot_len < (uint16_t)(WIFI_TX_MIN + ETH_PAD_SIZE)) ||
		(p->tot_len > (uint16_t)(WIFI_TX_MAX + ETH_PAD_SIZE))) {
		return ERR_BUF;
	}
	len = (uint16_t)(p->tot_len - ETH_PAD_SIZE);

	mutexLock(state->tx_lock);

	pbuf_copy_partial(p, state->tx_buf, len, ETH_PAD_SIZE);
	if (write(state->data_fd, state->tx_buf, len) != (ssize_t)len) {
		state->tx_err++;
		mutexUnlock(state->tx_lock);
		return ERR_IF;
	}
	state->tx_ok++;

	mutexUnlock(state->tx_lock);

	return ERR_OK;
}


static const char *wifi_media(struct netif *netif)
{
	wifi_state_t *state = netif->state;

	return state->joined ? "wifi/BCM43455 joined" : "wifi/BCM43455 unjoined";
}


static int wifi_stats(struct netif *netif, char *buf, size_t cap)
{
	wifi_state_t *state = netif->state;
	int r;

	r = snprintf(buf, cap,
		"rx=%lu rx_err=%lu rx_toobig=%lu tx=%lu tx_err=%lu link=%d ssid=\"%s\"",
		state->rx_ok, state->rx_err, state->rx_toobig,
		state->tx_ok, state->tx_err, state->link_up, state->ssid);

	return ((r > 0) && ((size_t)r < cap)) ? r : 0;
}


/* --- netif init -------------------------------------------------- */

static int wifi_netifInit(struct netif *netif, char *cfg)
{
	wifi_state_t *state = netif->state;
	int err;

	/* create_netif() malloc()s the state, so it arrives dirty; every flag here
	 * (link_up, dhcp_started, mac_valid, the counters) must start at zero. */
	memset(state, 0, sizeof(*state));
	state->netif = netif;
	state->data_fd = -1;
	state->ctl_fd = -1;

	err = wifi_parseCfg(state, cfg);
	if (err < 0) {
		return err;
	}

	/* The framework's mtu/hwaddr/flags defaults come from a strcmp chain over
	 * the known driver names, which this one does not match -- set them here.
	 * NETIF_FLAG_LINK_UP is deliberately NOT set: the link comes up only after
	 * the join succeeds. netif->output is already etharp_output (netif_dev_init
	 * sets it for every driver except tun/g3plc), so leave it alone. */
	MIB2_INIT_NETIF(netif, snmp_ifType_ethernet_csmacd, 0);
	netif->mtu = 1500;
	netif->hwaddr_len = 6;
	netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;
	netif->name[0] = 'w';
	netif->name[1] = 'l';

	netif->linkoutput = wifi_linkOutput;

	if (mutexCreate(&state->tx_lock) != 0) {
		wifi_printf("tx_lock mutexCreate failed");
		return -ENOMEM;
	}

	err = beginthread(wifi_rxThread, 4, state->rx_stack, sizeof(state->rx_stack), state);
	if (err != 0) {
		wifi_printf("rx thread failed: %d", err);
		return err;
	}

	/* Everything blocking -- waiting for the daemon's device files, the MAC
	 * query and the 20-40 s join -- happens here, off the tcpip thread that
	 * runs this init. */
	err = beginthread(wifi_joinThread, 4, state->join_stack, sizeof(state->join_stack), state);
	if (err != 0) {
		wifi_printf("join thread failed: %d", err);
		return err;
	}

	wifi_printf("netif registered (link down until the join completes)");

	return 0;
}


/* --- driver registration ---------------------------------------- */

static netif_driver_t wifi43455_drv = {
	.init = wifi_netifInit,
	.state_sz = sizeof(wifi_state_t),
	.state_align = _Alignof(wifi_state_t),
	.name = "wifi43455",
	.media = wifi_media,
	.stats = wifi_stats,
};


__constructor__(1000) void register_driver_wifi43455(void)
{
	register_netif_driver(&wifi43455_drv);
}
