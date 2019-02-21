#include "common.h"
#include "net.h"
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>

void neterr(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vneterr(fmt, ap);
    va_end(ap);
}

void die_neterr(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vneterr(fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

/* Returns 0 if entire buffer was sent, or error number otherwise. */
int send_entire_check(int sockfd, const void *buf, size_t len, int flags)
{
    size_t nleft = len;
    const char *ptr = buf;

    while (!terminate && nleft > 0) {
        ssize_t nsent = send(sockfd, ptr, nleft, flags);
        if (nsent >= 0) {
            nleft -= nsent;
            ptr += nsent;
        } else if (errno != EINTR) {
            neterr("Cannot send data");
            return errno;
        }
    }
    return nleft ? EINTR : 0;
}

/* Returns 0 if entire buffer was received, or error number otherwise. */
int recv_entire(int sockfd, void *buf, size_t len, int flags)
{
    size_t nleft = len;
    char *ptr = buf;

    while (!terminate && nleft > 0) {
        ssize_t nreceived = recv(sockfd, ptr, nleft, flags);
        if (nreceived > 0) {
            nleft -= nreceived;
            ptr += nreceived;
        } else if (nreceived == 0) {
            /* Peer closed the connection. */
            return ECONNCLOSED;
        } else if (errno != EINTR) {
            return errno;
        }
    }
    return nleft ? EINTR : 0;
}

int check_recv(int rc)
{
    if (rc == ECONNCLOSED) {
        err("Peer unexpectedly closed the connection");
    } else if (rc != EINTR && rc != 0) {
        neterr("Cannot receive data");
    }
    return rc;
}
