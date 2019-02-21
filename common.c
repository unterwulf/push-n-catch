#include "common.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

sig_atomic_t terminate = 0;
int g_verbose = 1;

void err(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

void info(const char *fmt, ...)
{
    if (g_verbose) {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
    }
}

void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}

void die_errno(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %s\n", strerror(errno));
    exit(EXIT_FAILURE);
}

fpp_off_t swap_offset(fpp_off_t off)
{
    fpp_off_t ret;
    char *src = (char *)&off;
    char *dst = (char *)&ret;
    size_t i;
    for (i = 0; i < 8; i++)
        dst[i] = src[7 - i];
    return ret;
}
