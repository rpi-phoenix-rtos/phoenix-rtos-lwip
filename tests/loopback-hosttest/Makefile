# Host test (Linux, no Pi, no cross-build): TCP over lwIP's loopback interface
# with the Raspberry Pi 4 options (core locking, inline input) and the port's
# own sys_arch primitives.
#
#   make run                     against this checkout (lib-lwip submodule checked out)
#   make run LWIP=<lib-lwip>     with the lwIP sources elsewhere
#   make run-tsan                the same under ThreadSanitizer

PORT   := ../..
LWIP   ?= $(PORT)/lib-lwip
LWIPDIR := $(LWIP)/src
include $(LWIPDIR)/Filelists.mk

LWIP_SRCS := $(COREFILES) $(CORE4FILES) $(APIFILES) $(LWIPDIR)/netif/ethernet.c
PORT_SRCS := $(addprefix $(PORT)/port/,semaphore.c mbox.c mutex.c protect.c)
SRCS   := $(LWIP_SRCS) $(PORT_SRCS) shim/hostsys.c loopback.c
CFLAGS ?= -std=gnu11 -O2 -g -Wall -Wno-unused-parameter -Wno-address
LDFLAGS := -Wl,--wrap=sys_mbox_trypost -lpthread
INCS   := -Ishim -I../sys-arch-hosttest/shim -I$(PORT)/include -I$(LWIP)/src/include

loopback: $(SRCS) shim/lwipopts.h
	$(CC) $(CFLAGS) $(INCS) -o $@ $(SRCS) $(LDFLAGS)

loopback-tsan: $(SRCS) shim/lwipopts.h
	$(CC) $(CFLAGS) -fsanitize=thread $(INCS) -o $@ $(SRCS) $(LDFLAGS)

run: loopback
	./loopback

run-tsan: loopback-tsan
	./loopback-tsan

clean:
	rm -f loopback loopback-tsan

.PHONY: run run-tsan clean
