#include "common.h"
#include "platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PATHSEP '\\'

const char *in_addr_str(in_addr_t addr)
{
    static char buf[sizeof "255.255.255.255"];
    return inet_ntoa(buf, addr);
}

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
        if ((S_IFMT & sb.st_mode) == S_IFREG)
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
    const char *src = buf;
    while (len && !terminate) {
        int nwritten = sock_fastwrite(sk, buf, len);
        if (nwritten > 0) {
            src += nwritten;
            len -= nwritten;
        }
        if (!tcp_tick(sk))
            return RV_CONNCLOSED;
    }
    return (len) ? RV_TERMINATED : 0;
}

/* Returns 0 if entire buffer was received, or error number otherwise. */
int recv_entire(Sock sk, void *buf, size_t len)
{
    char *dst = buf;
    while (len && !terminate) {
        int nread = sock_fastread(sk, dst, len);
        if (nread > 0) {
            dst += nread;
            len -= nread;
        }
        if (!tcp_tick(sk))
            return RV_CONNCLOSED;
    }
    return (len) ? RV_TERMINATED : 0;
}

fpp_off_t to_fpp_off(off_t off)
{
    fpp_off_t fpp_off;
    fpp_off.word[0] = off;
    fpp_off.word[1] = 0;
    return fpp_off;
}
