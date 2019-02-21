#ifndef COMMON_H
#define COMMON_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include "fpp.h"

#define CATCH_PORT 2121
#define DISCOVERY_VER 1
#define PEERNAME_MAX 255

#ifdef _WIN32
#define PATHSEP '\\'
#else
#define PATHSEP '/'
#endif

#define UNUSED(x) (void)(x)

sig_atomic_t terminate;
int g_verbose;

void err(const char *fmt, ...);
void info(const char *fmt, ...);
void die(const char *fmt, ...);
void die_errno(const char *fmt, ...);

#ifndef BYTE_ORDER_BIG_ENDIAN
#define hton_offset(off) swap_offset(off)
#define ntoh_offset(off) swap_offset(off)
#else
#define hton_offset(off) off
#define ntoh_offset(off) off
#endif
fpp_off_t swap_offset(fpp_off_t off);

#endif
