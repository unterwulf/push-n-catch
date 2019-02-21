#include "net.h"
#include "common.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void vneterr(const char *fmt, va_list ap)
{
    int wsa_last_error = WSAGetLastError();
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, ": %d\n", wsa_last_error);
}

void init_netlib(void)
{
    WSADATA wsaData;
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0)
        die("WSAStartup failed with error: %d", err);
}
