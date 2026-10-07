/* Host shim: Phoenix debug() writes one string to the console */
#ifndef SHIM_SYS_DEBUG_H
#define SHIM_SYS_DEBUG_H

#include <stdio.h>

#define debug(s) fputs((s), stderr)

#endif
