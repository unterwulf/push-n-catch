#ifndef COMMON_H
#define COMMON_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include "fpp.h"
#include "platform.h"

#define CATCH_PORT 2121
#define DISCOVERY_VER 1
#define PEERNAME_MAX 255

#define UNUSED(x) (void)(x)

extern volatile sig_atomic_t terminate;
extern int g_verbose;

void err(const char *fmt, ...);
void err_errno(const char *fmt, ...);
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

#define RV_TERMINATED 1
#define RV_NACK       3
#define RV_REJECT     4
#define RV_UNEXPECTED 5
#define RV_IOERROR    6
#define RV_NETIOERROR 7
#define RV_CONNCLOSED 8
#define RV_RESUME_ACK 9
#define RV_RESUME_NACK 10
#define RV_LOCAL_BIGGER 12
#define RV_NOENT 13
#define RV_NOT_REGULAR_FILE 14
#define RV_TOOBIG 15
#define RV_DIGEST_MATCH 16
#define RV_SIZE_MATCH 17
#define RV_COMPLETED_DIGEST_MISMATCH 18

static inline int send_short_msg(Sock sk, fpp_msg_t msg)
{
    return send_entire(sk, &msg, sizeof msg);
}

#endif
