#include "net.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

void vneterr(const char *fmt, va_list ap)
{
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %s\n", strerror(errno));
}

void init_netlib(void)
{
}
