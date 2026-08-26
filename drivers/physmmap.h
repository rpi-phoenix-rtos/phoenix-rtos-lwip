/*
 * Phoenix-RTOS --- networking stack
 *
 * Utilities: HW debugging helpers
 *
 * Copyright 2018 Phoenix Systems
 * Author: Michał Mirosław
 *
 * %LICENSE%
 */
#ifndef NETLIB_PHYSMMAP_H_
#define NETLIB_PHYSMMAP_H_

#include <stdint.h>
#include <sys/mman.h>


void *dmammap(size_t sz) __attribute__((malloc, alloc_size(1), assume_aligned(_PAGE_SIZE)));

/* Like dmammap(), but maps the contiguous region WRITE-BACK CACHEABLE instead of
 * uncached. The caller becomes responsible for explicit cache maintenance around
 * every DMA (clean before device-write, invalidate before CPU-read) — the
 * streaming-DMA model. Intended for high-throughput RX rings where touching the
 * payload uncached dominates; do NOT use for descriptors or any buffer shared with
 * a device without per-transfer cache ops. See the GENET cacheable RX path. */
void *dmammap_cached(size_t sz) __attribute__((malloc, alloc_size(1), assume_aligned(_PAGE_SIZE)));

volatile void *physmmap(addr_t addr, size_t sz);
void physunmap(volatile void *va, size_t sz);


#endif /* NETLIB_PHYSMMAP_H_ */
