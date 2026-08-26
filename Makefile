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

# Policy B (task #11): opt-in cacheable/streaming-DMA GENET RX path + integrity
# bench. DEFAULT-OFF — the stock build keeps the proven uncached RX path. Enable
# for the bench with `make GENET_RX_CACHEABLE=1 ...`; the -D reaches both the
# driver lib (drivers/bcm-genet.c) and the port lib (port/genet-rxcache-bench.c,
# port/main.c). See drivers/bcm-genet.c for the NEEDS-CAREFUL-HW-REVIEW notes.
ifeq ($(GENET_RX_CACHEABLE),1)
CFLAGS += -DGENET_RX_CACHEABLE=1
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
