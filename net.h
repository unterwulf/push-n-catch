#ifndef NET_H
#define NET_H

#include <stdarg.h>
#include <errno.h>

#define ECONNCLOSED EPIPE

void vneterr(const char *fmt, va_list ap);
void init_netlib(void);

#include "net_sys.h"

void neterr(const char *fmt, ...);
void die_neterr(const char *fmt, ...);

int send_entire_check(int sockfd, const void *buf, size_t len, int flags);
int recv_entire(int sockfd, void *buf, size_t len, int flags);
int check_recv(int rc);

static inline int recv_entire_check(int sockfd, void *buf, size_t len, int flags)
{
    return check_recv(recv_entire(sockfd, buf, len, flags));
}

#endif
