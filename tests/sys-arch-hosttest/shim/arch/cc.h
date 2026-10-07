/* Host shim for the port's arch/cc.h: its Phoenix byte-order and libc
 * definitions collide with glibc's, and these tests need none of them */
#ifndef SHIM_ARCH_CC_H
#define SHIM_ARCH_CC_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

__attribute__((cold, noreturn, format(printf, 1, 2))) void bail(const char *format, ...);
__attribute__((cold, noreturn, format(printf, 2, 3))) void errout(int err, const char *format, ...);

#define LWIP_PLATFORM_DIAG(x)   printf x
#define LWIP_PLATFORM_ASSERT    bail

#endif
