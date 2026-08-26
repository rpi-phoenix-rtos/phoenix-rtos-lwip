#
# Makefile for phoenix-rtos-lwip
#
# Copyright 2019-2021 Phoenix Systems
#
# %LICENSE%
#

include ../phoenix-rtos-build/Makefile.common

# set local path manually as we're including other Makefiles here (as an empty var - TOPDIR)
LOCAL_DIR :=

.DEFAULT_GOAL := all

LWIPOPTS_DIR ?= "include/default-opts"

# default path for the programs to be installed in rootfs
DEFAULT_INSTALL_PATH := /sbin

# core LwIP component
LWIPDIR := lib-lwip/src
include $(LWIPDIR)/Filelists.mk
LWIP_EXCLUDE := netif/slipif.c
LWIP_SRCS := $(filter-out $(addprefix $(LWIPDIR)/,$(LWIP_EXCLUDE)),$(LWIPNOAPPSFILES))

# G3-PLC modifications to core LwIP
ifeq ($(LWIP_G3_BUILD), yes)
CFLAGS := $(CFLAGS) -I./g3/
include g3/Makefile
endif

CFLAGS += -Wundef -Iinclude -Ilib-lwip/src/include -I"$(LWIPOPTS_DIR)"

# Cacheable/streaming-DMA GENET RX path. Now DEFAULT-ON in the driver (HW-
# validated bit-exact + GPU+net FB-clean, 2026-08-26; see bcm-genet.c). This
# forwards an explicit override to both the driver lib and the port lib, so
# `make GENET_RX_CACHEABLE=0 ...` rolls back to the uncached pool and
# `GENET_RX_CACHEABLE=1` is the (redundant) explicit enable.
ifneq ($(GENET_RX_CACHEABLE),)
CFLAGS += -DGENET_RX_CACHEABLE=$(GENET_RX_CACHEABLE)
endif

# Raw TCP throughput bench (gigabit-NFS "size the prize"): opt-in lwiperf TCP
# server (iperf 2.0.5 protocol) so a host `iperf -c <pi>` measures the
# lwip-core + driver RX ceiling WITHOUT the socket-copy / NFS-RPC layers above
# it — isolating whether the ~8 MB/s NFS-read ceiling is the driver drain or a
# higher layer. DEFAULT-OFF. Enable with `make LWIP_IPERF=1 ...`.
ifeq ($(LWIP_IPERF),1)
LWIP_SRCS += $(LWIPERFFILES)
CFLAGS += -DLWIP_IPERF=1
endif

# Expose the GENET driver's RX-stats console line (rx_polls/pollrescue/zerocopy/
# copyfb/drop/rbuf_ovfl/rxtmo, one line / 5 s) to the build. DEFAULT-OFF (keeps
# the shared console quiet, #31). Enable with `make GENET_RXSTATS_LOG=1 ...` to
# read the RX drain mechanism (IRQ- vs poll-clocked) during a throughput bench.
ifeq ($(GENET_RXSTATS_LOG),1)
CFLAGS += -DGENET_RXSTATS_LOG=1
endif

# Coalesce back-to-back TCP segments onto one recvmbox pbuf chain (gigabit-NFS
# Option B): folds the per-segment tcpip->socket handoff so the socket-recv path
# stops paying an mbox post/fetch + consumer wakeup per ~1448-byte segment. Only
# helps under a recv backlog (self-tuning: no queued entry -> normal post).
# Default is set by the guard in api_msg.c; this forwards an explicit override to
# the whole lwip build, so `make LWIP_RECVMBOX_COALESCE=0 ...` is the rollback
# off-switch and `=1` the explicit enable (same pattern as GENET_RX_CACHEABLE).
ifneq ($(LWIP_RECVMBOX_COALESCE),)
CFLAGS += -DLWIP_RECVMBOX_COALESCE=$(LWIP_RECVMBOX_COALESCE)
endif
ifeq ($(LWIP_G3_BUILD), yes)
CFLAGS += -I$(PREFIX_BUILD)/phrtos3-include -I$(PREFIX_PROJECT)/G3-PLC/ps_g3_phy/api/include
endif

# Raspberry Pi 4B: enable LwIP stats (LINK/IP/TCP/MEM counters + the /dev/ipstats
# dump device) as a standing network-diagnostic facility. The Pi 4 has 4 GB RAM so
# the counter overhead is negligible; memory-constrained MCU targets keep the
# stats-off default (this is scoped to aarch64a72-generic). Must be set BEFORE the
# lwip-core static-lib include below, or stats.c / the ip4.c+tcp_in.c increment
# sites would compile without it. LWIP_STATS is #ifndef-guarded in lwipopts.h, so
# this -D wins and turns on the LWIP_STATS sub-options block.
ifeq ($(TARGET_FAMILY)-$(TARGET_SUBFAMILY),aarch64a72-generic)
CFLAGS += -DLWIP_STATS=1
endif

NAME := lwip-core
SRCS := $(LWIP_SRCS)
# Disabling warnings from lib-lwip, as their code does not comply with these rules for now.
LOCAL_CFLAGS += -Wno-char-subscripts -Wno-format-zero-length
# don't install include subdir contents, these are actually internal headers
LOCAL_HEADER_DIR := nothing
include $(static-lib.mk)

# should define NET_DRIVERS and platform driver sources
-include _targets/Makefile.$(TARGET_FAMILY)-$(TARGET_SUBFAMILY)

ifeq (${LWIP_WIFI_BUILD},yes)
CFLAGS += -Iwi-fi/hal -Iwi-fi/lwip -Iwi-fi/whd
include wi-fi/hal/Makefile
include wi-fi/whd/Makefile
include wi-fi/lwip/Makefile
endif

ifeq (${LWIP_IPSEC_BUILD},yes)
include ipsec/Makefile
endif

include drivers/Makefile
include port/Makefile

DEFAULT_COMPONENTS := $(ALL_COMPONENTS)

# create generic targets
.PHONY: all install clean
all: $(DEFAULT_COMPONENTS)
install: $(patsubst %,%-install,$(DEFAULT_COMPONENTS))
clean: $(patsubst %,%-clean,$(ALL_COMPONENTS))
