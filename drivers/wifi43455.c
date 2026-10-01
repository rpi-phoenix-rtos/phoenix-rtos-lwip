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
 *                    "leave"                 -> disassociate
 *                    "status"                -> "STATUS joined=0|1 ..." (joined=0
 *                                               also after a lost association)
 *
 * Consequences for the netif lifecycle:
 *
 *   - The daemon starts at boot, but registers the device files only after
 *     its firmware download, i.e. AFTER lwIP is already running, so at init()
 *     time both are normally still absent. init() must not fail on that: it
 *     brings the netif up with the link DOWN and leaves all device I/O to a
 *     join thread that retries the opens forever.
 *   - The join itself takes 20-40 s and init() runs on the tcpip thread, so the
 *     join must not happen inline either -- same join thread.
 *   - DHCP is this driver's job (the daemon's `joinwpa` deliberately skips it):
 *     every link-up starts it and every leave releases the lease, both in the
 *     tcpip thread via netifapi_netif_common().
 *   - The join thread never exits. It keeps the association in line with the
 *     wanted credentials, so a network can be joined, changed or left at run
 *     time -- `wifi connect` / `wifi disconnect` just edit /etc/wifi.conf.
 *   - The default route stays with genet, the primary interface, unless genet
 *     has no address (e.g. SD boot with no cable); then WiFi takes it.
 *
 * Config string (everything after the first ':' of the boot token):
 *
 *   wifi43455:<ssid>:<psk>   credentials inline (psk is the whole remainder,
 *                            so it may itself contain ':')
 *   wifi43455                credentials from /etc/wifi.conf ("ssid=" / "psk="
 *                            key=value lines, '#' comments) so the boot config
 *                            carries no secret. Re-read every WIFI_WATCH_S.
 */
#include "netif-driver.h"

#include "lwip/dhcp.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
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
#define WIFI_IRQ_DEV  "/dev/wifiirq"
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

/* RX: interrupt first. When the daemon serves /dev/wifiirq, this thread drains
 * /dev/wifidata until it reads empty and then sleeps in a /dev/wifiirq read,
 * which returns when the chip raises its frame interrupt, or after the daemon's
 * fallback timeout (10 ms, the idle poll below) if none comes. The thread leaves
 * that mode for polling, for the rest of the boot, if the device is absent or
 * fails (`wifi rxpoll`), or if the interrupt evidently does not work:
 *
 *   - WIFI_IRQ_EMPTY_RUN wakeups in a row found nothing to read: the line is
 *     stuck (the ack does not clear it). Without the check that would spin.
 *   - at least WIFI_IRQ_MISSED_MIN frames, and more than there were
 *     wakeups, were found only by the read after a timeout: it does not fire.
 *
 * RX pacing when polling. /dev/wifidata never blocks, so without the interrupt
 * this thread polls: every read() is one IPC round trip plus one SDIO probe of
 * the chip's F2 FIFO (~22 us of bus time in the daemon). A fixed 200 us poll -- ~5000 probes a second -- is
 * what the link needs while frames flow, but on an idle joined link it cost a
 * CPU-bound game (vkQuake) ~10 % of its frame rate. So the interval adapts:
 *
 *   - after a received frame, poll every WIFI_RX_FAST_US for WIFI_RX_HOLD_RX
 *     more empty reads (a burst, or the rest of an aggregated superframe, is
 *     likely right behind it);
 *   - after a TRANSMITTED frame, stay fast for WIFI_RX_HOLD_TX empty reads
 *     (~20 ms): whatever we sent -- a TCP segment, an ACK, a ping, a DHCP or
 *     ARP request -- usually draws a reply, and the measured round trip to the
 *     AP is 2-6 ms. The transmit path also wakes a sleeping RX thread (see
 *     wifi_rxKick), so a reply never waits out an idle interval;
 *   - past the hold, the interval doubles on every empty read up to
 *     WIFI_RX_IDLE_MAX_US.
 *
 * Any flow in either direction therefore polls exactly as fast as before (both
 * TCP directions transmit: data one way, ACKs the other), and an idle link
 * settles at 100 probes a second instead of ~5000. The price is latency for an
 * UNSOLICITED frame arriving at an idle link -- at most WIFI_RX_IDLE_MAX_US
 * (5 ms on average), once, since that frame restores the fast rate.
 *
 * Throughput history, measured on hardware: 1500 us fixed gave 0.58 MB/s and
 * 200 us up to 1.73 (before later SDIO work raised it to TX 3.6 / RX 3.3). Treat
 * single runs as directional -- repeat runs of identical code spanned
 * 0.66-1.73 MB/s -- which is why the fast rate is kept exactly as it was. */
#define WIFI_RX_FAST_US     200u   /* poll interval while frames flow */
#define WIFI_RX_IDLE_MAX_US 10000u /* poll interval on an idle link */
#define WIFI_RX_HOLD_RX     8u     /* empty reads at the fast rate after an RX frame (~1.6 ms) */
#define WIFI_RX_HOLD_TX     100u   /* ... and after a TX frame (~20 ms) */

#define WIFI_IRQ_EMPTY_RUN 64u  /* interrupt mode: empty wakeups in a row = stuck line */
#define WIFI_IRQ_MISSED_MIN 32u /* ... frames found only after a timeout = no interrupt */

#define WIFI_RX_ERR_US    20000u  /* back off a little on a read error */
#define WIFI_DEV_RETRY_S  2u      /* device files appear when rpi4-wifi starts */
#define WIFI_RX_NOLINK_US 100000u /* not associated: nothing to receive */
#define WIFI_WATCH_S      3u  /* how often /etc/wifi.conf is re-read */
#define WIFI_JOIN_RETRY_S 10u /* failed join: wait 10 s, 20 s, ... */
#define WIFI_JOIN_BACKOFF_MAX 6u /* ... capped at 60 s */

#define WIFI_SSID_CAP 33u /* 32 + NUL, per IEEE 802.11 */
#define WIFI_PSK_CAP  65u /* 64 + NUL, per WPA2-PSK */


typedef struct {
	struct netif *netif;

	int data_fd; /* /dev/wifidata -- raw frames */
	int ctl_fd;  /* /dev/wifi     -- text commands */
	int irq_fd;  /* /dev/wifiirq  -- frame interrupts; -1 = poll. RX thread only, once set */

	/* Boot-cfg credentials (empty = use /etc/wifi.conf), and the ones the
	 * current or last join used. */
	char cfg_ssid[WIFI_SSID_CAP];
	char cfg_psk[WIFI_PSK_CAP];
	char ssid[WIFI_SSID_CAP];
	char psk[WIFI_PSK_CAP];

	uint8_t mac[6];
	bool mac_valid;
	bool joined;
	bool route_checked; /* default-route decision taken for this lease */

	/* Written by the join thread, read by linkoutput/media/stats on other
	 * threads. Plain int: a torn read is impossible on this target. A stale 0
	 * delays a TX; a stale 1 lets one frame reach a daemon that is leaving,
	 * which drops it -- both harmless. */
	volatile int link_up;

	handle_t tx_lock; /* lwIP may call linkoutput from several threads */

	/* TX -> RX wakeup (wifi_rxKick). tx_kicks counts transmitted frames;
	 * rx_napping is set while the RX thread sleeps on rx_cond through an idle
	 * interval. Both are accessed with __atomic builtins: the pair is a
	 * store-then-load handshake on each side, which needs full ordering. */
	handle_t rx_lock;
	handle_t rx_cond;
	unsigned int tx_kicks;
	int rx_napping;

	uint8_t tx_buf[WIFI_TX_MAX];
	uint8_t rx_buf[WIFI_RX_BUF];
	char resp[WIFI_RESP_MAX];

	unsigned long rx_ok;
	unsigned long rx_err;
	unsigned long rx_toobig;
	unsigned long tx_ok;
	unsigned long tx_err;

	/* Interrupt-mode RX (RX thread only). */
	unsigned long irq_wakes;    /* /dev/wifiirq reads that returned an interrupt */
	unsigned long irq_timeouts; /* ... that timed out */
	unsigned long irq_empty;    /* interrupts after which the FIFO read empty */
	unsigned long irq_missed;   /* frames found only by the read after a timeout */
	unsigned int irq_empty_run;

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
	if ((ssid_len >= sizeof(state->cfg_ssid)) || (strlen(sep + 1) >= sizeof(state->cfg_psk))) {
		wifi_printf("bad cfg: ssid or psk too long");
		return -EINVAL;
	}

	memcpy(state->cfg_ssid, cfg, ssid_len);
	state->cfg_ssid[ssid_len] = '\0';
	strcpy(state->cfg_psk, sep + 1);

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
 * Unknown keys are ignored. Fills ssid/psk (sized like the state fields) and
 * returns 0 only if BOTH were found; a missing file is just -ENOENT. */
static int wifi_readConf(char *ssid, char *psk)
{
	FILE *f = fopen(WIFI_CONF, "r");
	char line[192];
	char *key, *val, *eq;

	ssid[0] = '\0';
	psk[0] = '\0';
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

		if ((strcmp(key, "ssid") == 0) && (strlen(val) < WIFI_SSID_CAP)) {
			strcpy(ssid, val);
		}
		else if ((strcmp(key, "psk") == 0) && (strlen(val) < WIFI_PSK_CAP)) {
			strcpy(psk, val);
		}
	}
	fclose(f);

	return ((ssid[0] != '\0') && (psk[0] != '\0')) ? 0 : -ENOENT;
}


/* --- link up / down ---------------------------------------------- */

/* Whether an interface can actually carry default-routed traffic: it is up, has
 * its link, and holds an IPv4 address. */
static int wifi_canRoute(struct netif *n)
{
	return (n != NULL) && netif_is_up(n) && netif_is_link_up(n) &&
		!ip4_addr_isany(netif_ip4_addr(n));
}


/* Runs in the tcpip thread (via netifapi_netif_common): everything here touches
 * lwIP core state. Take the default route only from an interface that cannot
 * use it -- see wifi_joinThread. */
static void wifi_takeDefaultFn(struct netif *netif)
{
	if ((netif_default != netif) && !wifi_canRoute(netif_default) && wifi_canRoute(netif)) {
		wifi_printf("default route now via WiFi (%s)",
			(netif_default == NULL) ? "there was none" : "the primary interface has no address");
		netif_set_default(netif);
	}
}


static err_t wifi_linkUpFn(struct netif *netif)
{
	wifi_state_t *state = netif->state;
	err_t err;

	/* lwIP reads netif->hwaddr when it builds the ARP and DHCP frames, so the
	 * address must be in place BEFORE the link comes up. */
	memcpy(netif->hwaddr, state->mac, 6);
	netif->hwaddr_len = 6;

	/* Administratively UP too: dhcp_start() refuses with ERR_ARG (-16) unless
	 * netif_is_up(), and unlike genet we never get NETIF_FLAG_UP for free --
	 * netif_dev_init() applies that default only to a hardcoded list of driver
	 * names. Observed on hardware as `dhcp_start: -16` after a good join. */
	netif_set_up(netif);
	netif_set_link_up(netif);

	/* dhcp_start() after an earlier dhcp_release_and_stop() starts a fresh
	 * DISCOVER, which is exactly what a rejoin wants. */
	err = dhcp_start(netif);
	wifi_printf("dhcp_start: %d (0=ok); waiting for a lease", (int)err);

	return ERR_OK;
}


static void wifi_linkDownFn(struct netif *netif)
{
	struct netif *n;

	/* Release the lease while the link can still carry the DHCPRELEASE: the
	 * join thread clears link_up (which makes linkoutput refuse) only after
	 * this returns. */
	dhcp_release_and_stop(netif);
	netif_set_link_down(netif);
	netif_set_down(netif);

	/* If WiFi held the default route, hand it back to any interface that can
	 * still use it; otherwise leave none rather than a dead one. */
	if (netif_default == netif) {
		netif_set_default(NULL);
		NETIF_FOREACH(n)
		{
			if ((n != netif) && wifi_canRoute(n)) {
				netif_set_default(n);
				break;
			}
		}
	}
}


/* --- credentials watch -------------------------------------------- */

/* The credentials the netif should be joined with right now: the boot cfg's, if
 * it named any, else whatever /etc/wifi.conf holds at this moment. Returns 0
 * when both an ssid and a psk are known. */
static int wifi_wantedCreds(wifi_state_t *state, char *ssid, char *psk)
{
	if (state->cfg_ssid[0] != '\0') {
		strcpy(ssid, state->cfg_ssid);
		strcpy(psk, state->cfg_psk);
		return 0;
	}

	return wifi_readConf(ssid, psk);
}


/* Open both device files. The rpi4-wifi daemon starts at boot but registers
 * them only once the chip runs its firmware, so this normally fails for the
 * first few seconds of uptime. */
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

	/* Optional: an older daemon, or one started with `pollrx`, has none, and the
	 * RX thread polls. The daemon creates it before /dev/wifidata, so it is
	 * there by the time the open above succeeds. */
	state->irq_fd = open(WIFI_IRQ_DEV, O_RDONLY);

	/* Publish data_fd only once BOTH opens succeeded: the RX thread polls that
	 * field, and a half-open state would have it read from a descriptor this
	 * thread is about to close. irq_fd is set before it, for the same reason. */
	state->ctl_fd = ctl_fd;
	__atomic_store_n(&state->data_fd, data_fd, __ATOMIC_RELEASE);

	return 0;
}


/* One WPA2 join attempt with the credentials in state->ssid/psk. On success the
 * link is up and DHCP is running. Returns 0 on success. */
static int wifi_join(wifi_state_t *state)
{
	char cmd[128];
	int n = snprintf(cmd, sizeof(cmd), "joinwpa %s %s", state->ssid, state->psk);

	if ((n < 0) || (n >= (int)sizeof(cmd))) {
		wifi_printf("ssid/psk too long for a joinwpa command");
		return -EINVAL;
	}

	wifi_printf("joining \"%s\" (WPA2 associate + 4-way key, 20-40s)", state->ssid);
	if (wifi_command(state, cmd) < 0) {
		wifi_printf("joinwpa: no reply from %s", WIFI_CTL_DEV);
		return -EIO;
	}
	if (strstr(state->resp, "JOINWPA ok") == NULL) {
		/* The reply's first line carries setssid=/psksup=/link= detail. */
		wifi_printf("joinwpa failed: %s", state->resp);
		return -ECONNREFUSED;
	}

	/* The MAC is echoed by the joinwpa reply too, in case the `mac` query at
	 * startup failed; the link must not come up without it. */
	if (!state->mac_valid && (wifi_parseMac(state->resp, state->mac) == 0)) {
		state->mac_valid = true;
	}
	if (!state->mac_valid) {
		wifi_printf("joined \"%s\" but the station MAC is unknown; leaving", state->ssid);
		(void)wifi_command(state, "leave");
		return -ENODEV;
	}

	state->joined = true;
	state->link_up = 1;
	(void)netifapi_netif_common(state->netif, NULL, wifi_linkUpFn);
	state->route_checked = false;
	wifi_printf("joined \"%s\"; link up", state->ssid);

	return 0;
}


/* Tear the association down: release the lease and drop the link first (while
 * frames can still go out), then tell the daemon to disassociate. */
static void wifi_leave(wifi_state_t *state)
{
	wifi_printf("leaving \"%s\"", state->ssid);
	(void)netifapi_netif_common(state->netif, wifi_linkDownFn, NULL);
	state->link_up = 0;
	state->joined = false;
	if (wifi_command(state, "leave") < 0) {
		wifi_printf("leave: no reply from %s", WIFI_CTL_DEV);
	}
}


/* Sleep up to `secs`, but return early once the wanted credentials stop being
 * the ones in state->ssid/psk -- so a corrected `wifi connect` during a long
 * back-off takes effect within WIFI_WATCH_S, not at the next attempt. */
static void wifi_backoff(wifi_state_t *state, unsigned secs)
{
	char ssid[sizeof(state->ssid)];
	char psk[sizeof(state->psk)];
	unsigned slept;

	for (slept = 0; slept < secs; slept += WIFI_WATCH_S) {
		sleep(WIFI_WATCH_S);
		if ((wifi_wantedCreds(state, ssid, psk) != 0) ||
			(strcmp(ssid, state->ssid) != 0) || (strcmp(psk, state->psk) != 0)) {
			return;
		}
	}
}


/* --- join thread (supervisor) -------------------------------------- */

/* Keeps the association in line with the wanted credentials for as long as the
 * netif exists. /etc/wifi.conf is the whole control interface: `wifi connect`
 * rewrites it and `wifi disconnect` removes it, and this loop notices within
 * WIFI_WATCH_S. It compares CONTENT, not mtime -- over NFS an mtime goes through
 * attribute caching, and this bench steps its clock at boot. */
static void wifi_joinThread(void *arg)
{
	wifi_state_t *state = arg;
	char ssid[sizeof(state->ssid)];
	char psk[sizeof(state->psk)];
	bool waiting_logged = false;
	unsigned fails = 0;
	int have;

	/* Wait for the daemon indefinitely but cheaply -- there is no sensible
	 * "give up" point: it starts at boot but loads its firmware first, and it
	 * can also be (re)started from the shell at any time. */
	while (wifi_openDevs(state) < 0) {
		if (!waiting_logged) {
			wifi_printf("waiting for %s (the rpi4-wifi daemon)", WIFI_DATA_DEV);
			waiting_logged = true;
		}
		sleep(WIFI_DEV_RETRY_S);
	}
	wifi_printf("%s + %s open; RX mode: %s", WIFI_DATA_DEV, WIFI_CTL_DEV,
		(state->irq_fd >= 0) ? "irq (" WIFI_IRQ_DEV ")" : "poll (no " WIFI_IRQ_DEV ")");

	if ((wifi_command(state, "mac") == 0) && (wifi_parseMac(state->resp, state->mac) == 0)) {
		state->mac_valid = true;
		wifi_printf("MAC %02x:%02x:%02x:%02x:%02x:%02x",
			state->mac[0], state->mac[1], state->mac[2],
			state->mac[3], state->mac[4], state->mac[5]);
	}

	/* Credentials are read only once the device files exist, never before: on
	 * netboot lwip starts on a dummyfs "/" and the real root (holding both the
	 * firmware the daemon loads and /etc/wifi.conf) is taken over later. */
	waiting_logged = false;
	for (;;) {
		have = (wifi_wantedCreds(state, ssid, psk) == 0);

		if (state->joined) {
			if (have && (strcmp(ssid, state->ssid) == 0) && (strcmp(psk, state->psk) == 0)) {
				/* Steady state. A DHCP lease arrives a few seconds after the
				 * join; once it has, check the default route once. */
				if (!state->route_checked && !ip4_addr_isany(netif_ip4_addr(state->netif))) {
					(void)netifapi_netif_common(state->netif, wifi_takeDefaultFn, NULL);
					state->route_checked = true;
				}
				sleep(WIFI_WATCH_S);

				/* The daemon notices a deauth, a disassoc or the link dropping
				 * (the AP went away) and reports joined=0; rejoin then, rather
				 * than keep a lease on a link that no longer carries frames. */
				if ((wifi_command(state, "status") == 0) && (strstr(state->resp, "joined=0") != NULL)) {
					wifi_printf("association with \"%s\" lost; rejoining", state->ssid);
					wifi_leave(state);
					fails = 0;
				}
				continue;
			}
			wifi_leave(state);
			fails = 0;
		}

		if (!have) {
			if (!waiting_logged) {
				wifi_printf("no credentials (boot cfg empty, no ssid=/psk= in %s); "
					"waiting -- run `wifi connect <ssid> <psk>`", WIFI_CONF);
				waiting_logged = true;
			}
			sleep(WIFI_WATCH_S);
			continue;
		}
		waiting_logged = false;

		strcpy(state->ssid, ssid);
		strcpy(state->psk, psk);
		if (wifi_join(state) == 0) {
			fails = 0;
			continue;
		}

		/* Keep trying for as long as these credentials are wanted -- the AP may
		 * simply be out of range -- but back off, so a wrong key does not keep
		 * the daemon's single thread (and with it every RX read) busy for 30 s
		 * of every 40. */
		if (fails < WIFI_JOIN_BACKOFF_MAX) {
			fails++;
		}
		wifi_backoff(state, WIFI_JOIN_RETRY_S * fails);
	}
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


/* Called after every transmitted frame: count it, and wake the RX thread if it
 * is sleeping through an idle interval, so the reply is picked up at the fast
 * rate. Only the (rare) wakeup takes a lock; the common case is two atomics. */
static void wifi_rxKick(wifi_state_t *state)
{
	(void)__atomic_fetch_add(&state->tx_kicks, 1u, __ATOMIC_SEQ_CST);
	if (__atomic_load_n(&state->rx_napping, __ATOMIC_SEQ_CST) != 0) {
		mutexLock(state->rx_lock);
		(void)condSignal(state->rx_cond);
		mutexUnlock(state->rx_lock);
	}
}


/* Sleep up to `us`, or until wifi_rxKick() reports a frame transmitted after
 * the one counted in `seen`. No kick can be lost: one that lands before
 * rx_napping is raised is caught by the re-check below, and one that lands
 * after it sees the flag and signals -- which it can only do once condWait()
 * has released rx_lock, i.e. once this thread is actually waiting. */
static void wifi_rxNap(wifi_state_t *state, unsigned int seen, unsigned int us)
{
	mutexLock(state->rx_lock);
	__atomic_store_n(&state->rx_napping, 1, __ATOMIC_SEQ_CST);
	if (__atomic_load_n(&state->tx_kicks, __ATOMIC_SEQ_CST) == seen) {
		(void)condWait(state->rx_cond, state->rx_lock, (time_t)us);
	}
	__atomic_store_n(&state->rx_napping, 0, __ATOMIC_SEQ_CST);
	mutexUnlock(state->rx_lock);
}


/* What led to an interrupt-mode data read. */
#define WIFI_WAKE_FRAME   0 /* the previous read returned a frame: drain on */
#define WIFI_WAKE_IRQ     1 /* /dev/wifiirq returned an interrupt */
#define WIFI_WAKE_TIMEOUT 2 /* /dev/wifiirq timed out: a fallback poll */


/* Leave interrupt mode for polling, for the rest of this boot. */
static void wifi_rxIrqOff(wifi_state_t *state, const char *why)
{
	wifi_printf("RX mode: poll (%s; irq wakes=%lu timeouts=%lu empty=%lu missed=%lu)", why,
		state->irq_wakes, state->irq_timeouts, state->irq_empty, state->irq_missed);
	close(state->irq_fd);
	state->irq_fd = -1;
}


/* One interrupt-mode step: a data read, and after an empty one, the wait for
 * the next interrupt. Returns what leads to the next read. */
static int wifi_rxIrqStep(wifi_state_t *state, int wake)
{
	ssize_t n;
	char c;

	n = read(state->data_fd, state->rx_buf, sizeof(state->rx_buf));
	if (n > 0) {
		if (wake == WIFI_WAKE_TIMEOUT) {
			state->irq_missed++; /* queued, but no interrupt said so */
		}
		state->irq_empty_run = 0u;
		wifi_deliverRx(state, (size_t)n);
		return WIFI_WAKE_FRAME;
	}
	if (n < 0) {
		if (errno == EMSGSIZE) {
			state->rx_toobig++;
		}
		else {
			state->rx_err++;
		}
		usleep(WIFI_RX_ERR_US);
		return WIFI_WAKE_FRAME;
	}

	/* Empty: the daemon reads past non-data frames while this path is on, so
	 * the FIFO really is drained, and the chip will interrupt for the next. */
	if (wake == WIFI_WAKE_IRQ) {
		state->irq_empty++;
		state->irq_empty_run++;
		if (state->irq_empty_run >= WIFI_IRQ_EMPTY_RUN) {
			wifi_rxIrqOff(state, "interrupt keeps firing with nothing queued");
			return WIFI_WAKE_FRAME;
		}
	}
	if ((state->irq_missed >= WIFI_IRQ_MISSED_MIN) && (state->irq_missed > state->irq_wakes)) {
		wifi_rxIrqOff(state, "frames arrive without an interrupt");
		return WIFI_WAKE_FRAME;
	}

	n = read(state->irq_fd, &c, 1);
	if (n == 1) {
		state->irq_wakes++;
		return WIFI_WAKE_IRQ;
	}
	if (n == 0) {
		state->irq_timeouts++;
		return WIFI_WAKE_TIMEOUT;
	}
	wifi_rxIrqOff(state, "the daemon switched the interrupt off");
	return WIFI_WAKE_FRAME;
}


static void wifi_rxThread(void *arg)
{
	wifi_state_t *state = arg;
	unsigned int seen = 0u;                  /* tx_kicks value last acted on */
	unsigned int hold = 0u;                  /* empty reads left at the fast rate */
	unsigned int interval = WIFI_RX_FAST_US; /* current idle interval */
	int wake = WIFI_WAKE_FRAME;              /* interrupt mode: why the next read happens */
	unsigned int kicks;
	ssize_t n;

	for (;;) {
		/* The join thread owns the opens; until they land there is nothing to
		 * poll. No lock is held across read(): during the 20-40 s join the
		 * daemon's single message thread is busy and this read queues behind
		 * it, which must not stall TX or the join. */
		if (__atomic_load_n(&state->data_fd, __ATOMIC_ACQUIRE) < 0) {
			sleep(WIFI_DEV_RETRY_S);
			continue;
		}
		/* Not associated: no data frame can arrive, and every empty read is a
		 * round trip to the daemon plus an SDIO probe -- ~4000 a second from a
		 * radio that is up but joined to nothing, which is every boot without
		 * /etc/wifi.conf now that the daemon starts at boot. */
		if (state->link_up == 0) {
			usleep(WIFI_RX_NOLINK_US);
			continue;
		}

		if (state->irq_fd >= 0) {
			wake = wifi_rxIrqStep(state, wake);
			continue;
		}

		/* Something went out since the last look: its reply is on the way. */
		kicks = __atomic_load_n(&state->tx_kicks, __ATOMIC_SEQ_CST);
		if (kicks != seen) {
			seen = kicks;
			hold = WIFI_RX_HOLD_TX;
			interval = WIFI_RX_FAST_US;
		}

		n = read(state->data_fd, state->rx_buf, sizeof(state->rx_buf));
		if (n > 0) {
			/* Read again at once: more may be queued behind this frame. */
			wifi_deliverRx(state, (size_t)n);
			if (hold < WIFI_RX_HOLD_RX) {
				hold = WIFI_RX_HOLD_RX;
			}
			interval = WIFI_RX_FAST_US;
		}
		else if (n == 0) {
			/* Nothing queued (read() never blocks): stay fast while a reply
			 * or a burst is expected, then back off towards the idle rate. */
			if (hold > 0u) {
				hold--;
				usleep(WIFI_RX_FAST_US);
			}
			else {
				interval = (interval >= (WIFI_RX_IDLE_MAX_US / 2u)) ? WIFI_RX_IDLE_MAX_US : (interval * 2u);
				wifi_rxNap(state, seen, interval);
			}
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

	wifi_rxKick(state);

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
		"rx=%lu rx_err=%lu rx_toobig=%lu tx=%lu tx_err=%lu link=%d ssid=\"%s\" "
		"rxmode=%s irq_wakes=%lu irq_timeouts=%lu irq_empty=%lu irq_missed=%lu",
		state->rx_ok, state->rx_err, state->rx_toobig,
		state->tx_ok, state->tx_err, state->link_up, state->ssid,
		(state->irq_fd >= 0) ? "irq" : "poll", state->irq_wakes, state->irq_timeouts,
		state->irq_empty, state->irq_missed);

	return ((r > 0) && ((size_t)r < cap)) ? r : 0;
}


/* --- netif init -------------------------------------------------- */

static int wifi_netifInit(struct netif *netif, char *cfg)
{
	wifi_state_t *state = netif->state;
	int err;

	/* create_netif() malloc()s the state, so it arrives dirty; every flag here
	 * (link_up, joined, mac_valid, the counters) must start at zero. */
	memset(state, 0, sizeof(*state));
	state->netif = netif;
	state->data_fd = -1;
	state->ctl_fd = -1;
	state->irq_fd = -1;

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

	if ((mutexCreate(&state->tx_lock) != 0) || (mutexCreate(&state->rx_lock) != 0) ||
		(condCreate(&state->rx_cond) != 0)) {
		wifi_printf("lock/cond creation failed");
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
