# Host test (Linux, no Pi, no cross-build) for the port's sys_arch primitives:
# semaphores, mailboxes, the TCPIP core mutex and the SYS_ARCH_PROTECT lock.
#
#   make run                     against this checkout (lib-lwip submodule checked out)
#   make run LWIP=<lib-lwip>     with the lwIP sources elsewhere
#   make run-tsan                the same under ThreadSanitizer
#
# Compiles the port's own port/{semaphore,mbox,mutex,protect}.c, not copies,
# against host pthreads. It checks the port's logic (predicates, timeouts,
# wake-ups); libphoenix's pthread implementation has its own tests.

PORT   := ../..
LWIP   ?= $(PORT)/lib-lwip
SRCS   := $(addprefix $(PORT)/port/,semaphore.c mbox.c mutex.c protect.c) synctest.c
CFLAGS ?= -std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-unused-parameter
INCS   := -Ishim -I$(PORT)/include -I$(LWIP)/src/include

synctest: $(SRCS) $(PORT)/port/sys_sync.h $(PORT)/include/arch/sys_arch.h
	$(CC) $(CFLAGS) $(INCS) -o $@ $(SRCS) -lpthread

synctest-tsan: $(SRCS) $(PORT)/port/sys_sync.h $(PORT)/include/arch/sys_arch.h
	$(CC) $(CFLAGS) -fsanitize=thread $(INCS) -o $@ $(SRCS) -lpthread

run: synctest
	./synctest

run-tsan: synctest-tsan
	./synctest-tsan

clean:
	rm -f synctest synctest-tsan

.PHONY: run run-tsan clean
