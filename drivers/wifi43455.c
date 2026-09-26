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
 *
 * Consequences for the netif lifecycle:
 *
 *   - The daemon is started from the shell, i.e. AFTER lwIP is already running,
 *     so at init() time both device files are normally still absent. init()
 *     must not fail on that: it brings the netif up with the link DOWN and
 *     leaves all device I/O to a join thread that retries the opens forever.
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
/* Idle RX pause. The daemon now WAITS for a frame inside read() (bounded), so
 * an empty return already means it waited, and this is only a safety valve
 * against a read that fails fast -- not the pacing mechanism it used to be.
 *
 * History, measured on hardware: 1500 us gave 0.58 MB/s (402 frames/s =
 * 2.49 ms/frame, i.e. the poll interval plus processing) and 200 us gave up to
 * 1.73. Treat that as directional, not exact -- repeat runs of identical code
 * later spanned 0.66-1.73 MB/s, so a single throughput run on this link cannot
 * settle a comparison. The reliable measurement is per-frame cost inside the
 * daemon: 178 us to receive a frame, 121 us to transmit one, but 1.1 MILLION
 * empty probes burning 24.9 s of bus time. Polling is the bottleneck, not the
 * radio or the SDIO. */
#define WIFI_RX_IDLE_US   200u
#define WIFI_RX_ERR_US    20000u /* back off a little on a read error */
#define WIFI_DEV_RETRY_S  2u     /* device files appear when rpi4-wifi starts */
#define WIFI_WATCH_S      3u  /* how often /etc/wifi.conf is re-read */
#define WIFI_JOIN_RETRY_S 10u /* failed join: wait 10 s, 20 s, ... */
#define WIFI_JOIN_BACKOFF_MAX 6u /* ... capped at 60 s */

#define WIFI_SSID_CAP 33u /* 32 + NUL, per IEEE 802.11 */
#define WIFI_PSK_CAP  65u /* 64 + NUL, per WPA2-PSK */


typedef struct {
	struct netif *netif;

	int data_fd; /* /dev/wifidata -- raw frames */
	int ctl_fd;  /* /dev/wifi     -- text commands */

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
	 * "give up" point: the operator may start rpi4-wifi at any time. */
	while (wifi_openDevs(state) < 0) {
		if (!waiting_logged) {
			wifi_printf("waiting for %s (start the rpi4-wifi daemon)", WIFI_DATA_DEV);
			waiting_logged = true;
		}
		sleep(WIFI_DEV_RETRY_S);
	}
	wifi_printf("%s + %s open", WIFI_DATA_DEV, WIFI_CTL_DEV);

	if ((wifi_command(state, "mac") == 0) && (wifi_parseMac(state->resp, state->mac) == 0)) {
		state->mac_valid = true;
		wifi_printf("MAC %02x:%02x:%02x:%02x:%02x:%02x",
			state->mac[0], state->mac[1], state->mac[2],
			state->mac[3], state->mac[4], state->mac[5]);
	}

	/* Credentials are read only once the device files exist, never before: on
	 * netboot lwip starts on a dummyfs "/" and the real root (holding both the
	 * rpi4-wifi binary and /etc/wifi.conf) is taken over later. */
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
	 * (link_up, joined, mac_valid, the counters) must start at zero. */
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
