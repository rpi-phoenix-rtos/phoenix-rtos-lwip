/*
 * Phoenix-RTOS
 *
 * BCM43455 WiFi: the frame-batch format of /dev/wifibatch
 *
 * Copyright 2026 Phoenix Systems
 *
 * %LICENSE%
 *
 * The two ends of /dev/wifibatch keep byte-identical copies of this file:
 * phoenix-rtos-devices wifi/rpi4-wifi/wifibatch.h (the rpi4-wifi daemon) and
 * phoenix-rtos-lwip drivers/wifibatch.h (the wifi43455 netif).
 *
 * /dev/wifidata moves one 802.3 frame per message, so every frame costs one IPC
 * round trip through the daemon's single message thread. /dev/wifibatch moves
 * several frames per message, packed into one buffer:
 *
 *   batch  = header record...
 *   header = u16 count, u16 flags                 (little-endian)
 *   record = u16 len, u16 0, len bytes of frame, zero pad to a multiple of 4
 *
 * The buffer ends exactly after the last record.
 *
 *   write()  count >= 1 frames to transmit, flags 0. Returns how many frames the
 *            daemon took, counted from the front. Fewer than count means the
 *            firmware's credit window closed: the rest were not sent, and they
 *            are still the caller's to send.
 *   read()   0 = nothing queued; otherwise one batch of count >= 1 frames.
 *            WIFIBATCH_F_DRAINED: the read ended because the receive FIFO read
 *            empty, so an interrupt-driven reader can wait for the next interrupt
 *            without first confirming with another read.
 */

#ifndef WIFIBATCH_H
#define WIFIBATCH_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>


#define WIFIBATCH_HDR     4u /* u16 count, u16 flags */
#define WIFIBATCH_REC_HDR 4u /* u16 len, u16 0 */
#define WIFIBATCH_LEN_MAX 0xffffu

#define WIFIBATCH_F_DRAINED 0x0001u


static inline uint16_t wifibatch_get16(const uint8_t *p)
{
	return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}


static inline void wifibatch_put16(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xffu);
	p[1] = (uint8_t)((v >> 8) & 0xffu);
}


/* Bytes a frame of `len` bytes takes in a batch. */
static inline uint32_t wifibatch_recSize(uint32_t len)
{
	return (WIFIBATCH_REC_HDR + len + 3u) & ~3u;
}


/* ---- writing ---------------------------------------------------------- */

typedef struct {
	uint8_t *buf;
	uint32_t cap;
	uint32_t len;   /* bytes used, the header included */
	uint32_t count; /* frames */
} wifibatch_t;


static inline void wifibatch_init(wifibatch_t *b, uint8_t *buf, uint32_t cap)
{
	b->buf = buf;
	b->cap = cap;
	b->len = WIFIBATCH_HDR;
	b->count = 0u;
}


/* Where to put the next frame, if one of up to `max` bytes fits; else NULL.
 * The slot is 4-byte aligned when the buffer is. */
static inline uint8_t *wifibatch_slot(const wifibatch_t *b, uint32_t max)
{
	if ((b->cap < b->len) || (max > WIFIBATCH_LEN_MAX) || (b->count >= WIFIBATCH_LEN_MAX) ||
		(wifibatch_recSize(max) > (b->cap - b->len))) {
		return NULL;
	}
	return b->buf + b->len + WIFIBATCH_REC_HDR;
}


/* Append the frame just written into the slot; `len` is at most the `max` the
 * slot was asked for. */
static inline void wifibatch_commit(wifibatch_t *b, uint32_t len)
{
	uint8_t *r = b->buf + b->len;
	uint32_t size = wifibatch_recSize(len);

	wifibatch_put16(r, len);
	wifibatch_put16(r + 2, 0u);
	memset(r + WIFIBATCH_REC_HDR + len, 0, size - WIFIBATCH_REC_HDR - len);
	b->len += size;
	b->count++;
}


/* Write the header. Returns the number of bytes to send. */
static inline uint32_t wifibatch_finish(wifibatch_t *b, uint32_t flags)
{
	wifibatch_put16(b->buf, b->count);
	wifibatch_put16(b->buf + 2, flags);
	return b->len;
}


/* Remove the first n frames (those the daemon took), keeping the rest in order
 * at the front of the buffer. */
static inline void wifibatch_drop(wifibatch_t *b, uint32_t n)
{
	uint32_t off = WIFIBATCH_HDR;
	uint32_t i;

	if (n >= b->count) {
		b->len = WIFIBATCH_HDR;
		b->count = 0u;
		return;
	}
	for (i = 0u; i < n; ++i) {
		off += wifibatch_recSize(wifibatch_get16(b->buf + off));
	}
	memmove(b->buf + WIFIBATCH_HDR, b->buf + off, b->len - off);
	b->len -= off - WIFIBATCH_HDR;
	b->count -= n;
}


/* ---- reading ---------------------------------------------------------- */

typedef struct {
	const uint8_t *buf;
	uint32_t off;   /* next record */
	uint32_t left;  /* records not yet returned */
	uint32_t flags;
} wifibatch_rd_t;


/* Check a received batch end to end before anything in it is used. Returns its
 * frame count (>= 1), or -1 if it is not a well-formed batch: short, empty, a
 * record running past the end, a non-zero reserved field, or bytes after the
 * last record. */
static inline int wifibatch_open(wifibatch_rd_t *r, const uint8_t *buf, size_t len)
{
	uint32_t count, off = WIFIBATCH_HDR, size, i;

	if ((len < WIFIBATCH_HDR) || (len > 0x7fffffffu)) {
		return -1;
	}
	count = wifibatch_get16(buf);
	if (count == 0u) {
		return -1;
	}
	for (i = 0u; i < count; ++i) {
		if (((uint32_t)len - off) < WIFIBATCH_REC_HDR) {
			return -1;
		}
		if (wifibatch_get16(buf + off + 2u) != 0u) {
			return -1;
		}
		size = wifibatch_recSize(wifibatch_get16(buf + off));
		if (size > ((uint32_t)len - off)) {
			return -1;
		}
		off += size;
	}
	if (off != (uint32_t)len) {
		return -1;
	}

	r->buf = buf;
	r->off = WIFIBATCH_HDR;
	r->left = count;
	r->flags = wifibatch_get16(buf + 2);
	return (int)count;
}


/* The next frame of an opened batch, or NULL after the last one. */
static inline const uint8_t *wifibatch_next(wifibatch_rd_t *r, uint32_t *len)
{
	const uint8_t *f;

	if (r->left == 0u) {
		return NULL;
	}
	*len = wifibatch_get16(r->buf + r->off);
	f = r->buf + r->off + WIFIBATCH_REC_HDR;
	r->off += wifibatch_recSize(*len);
	r->left--;
	return f;
}

#endif /* WIFIBATCH_H */
