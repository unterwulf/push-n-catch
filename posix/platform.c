#include "common.h"
#include "platform.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define PATHSEP '/'

const char *basename(const char *pathname)
{
    char *base = strrchr(pathname, PATHSEP);
    return base ? (base + 1) : pathname;
}

void sanitize_filename(char *filename)
{
    char *p = filename;
    for (; *p; p++) {
        if (*p == PATHSEP)
            *p = '_';
    }
}

int get_filelen(const char *filename, off_t *filelen)
{
    struct stat sb;
    int rv = stat(filename, &sb);
    if (!rv) {
        if (S_ISREG(sb.st_mode))
            *filelen = sb.st_size;
        else
            rv = RV_NOT_REGULAR_FILE;
    } else if (errno == ENOENT) {
        rv = RV_NOENT;
    } else {
        rv = RV_IOERROR;
    }
    return rv;
}

/* Returns 0 if entire buffer was sent, or error number otherwise. */
int send_entire(Sock sk, const void *buf, size_t len)
{
    size_t nleft = len;
    const char *ptr = buf;

    while (!terminate && nleft > 0) {
        ssize_t nsent = send(sk, ptr, nleft, MSG_NOSIGNAL);
        if (nsent >= 0) {
            nleft -= nsent;
            ptr += nsent;
        } else if (errno == EPIPE || errno == ECONNRESET) {
            /* Peer closed the connection. */
            return RV_CONNCLOSED;
        } else if (errno != EINTR) {
            return RV_NETIOERROR;
        }
    }
    return nleft ? RV_TERMINATED : 0;
}

/* Returns 0 if entire buffer was received, or error number otherwise. */
int recv_entire(Sock sk, void *buf, size_t len)
{
    size_t nleft = len;
    char *ptr = buf;

    while (!terminate && nleft > 0) {
        ssize_t nreceived = recv(sk, ptr, nleft, 0);
        if (nreceived > 0) {
            nleft -= nreceived;
            ptr += nreceived;
        } else if (nreceived == 0) {
            /* Peer closed the connection. */
            return RV_CONNCLOSED;
        } else if (errno != EINTR) {
            return RV_NETIOERROR;
        }
    }
    return nleft ? RV_TERMINATED : 0;
}
