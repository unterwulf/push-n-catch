#include "common.h"
#include "dospush.h"
#include <tcp.h>

#include <dos.h>
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/* Default 4K stack is too small. */
extern unsigned _stklen = 8192;

/* DOS machines are usually slow, so let them not to validate digests
 * by default. */
int use_digests = 0;

/* Use forced push in the push mode, allow forced pushes in the catch mode. */
int use_force = 0;

tcp_Socket tcp_sk;
udp_Socket udp_sk;
char udp_skbuf[UDP_BACKLOG_SIZE];

static const char *argv0;
static void interrupt (*old_int1b)(void);

int is_int_pending(void *sock)
{
    UNUSED(sock);
    return terminate;
}

static void interrupt int1b(void)
{
    terminate = 1;
}

static void restore_int1b(void)
{
    setvect(0x1B, old_int1b);
}

static const char *conffile(const char *filename)
{
    static char name[_MAX_PATH];
    const char *path = getenv(filename);
    size_t pathlen = 0;
    int fd;

    if (path) {
        pathlen = strlen(path);
    } else {
        char *lastslash = strrchr(argv0, '\\');
        if (lastslash) {
            path = argv0;
            pathlen = lastslash - path;
        }
    }

    if (pathlen) {
        if (pathlen + strlen(filename) + 1 > sizeof name)
            return NULL;
        memcpy(name, path, pathlen);
        name[pathlen++] = '\\';
    }
    name[pathlen] = '\0';
    strcat(name, filename);

    if ((fd = open(name, O_RDONLY | O_TEXT)) >= 0) {
        close(fd);
        return name;
    }

    return NULL;
}

void init_wattcp(void)
{
    tzset();
    if (sock_init(conffile("WATTCP.CFG")) != 0)
        die("Could not initialize network");

    /* WatTCP setups its Ctrl-C handler that never aborts the program,
     * so hopefully we will never leave the system with our Ctrl/Break
     * interrupt handler after returning to DOS. */

    /* Setup our own Ctrl/Break interrupt handler */
    old_int1b = getvect(0x1B);
    atexit(restore_int1b);
    setvect(0x1B, int1b);
}

void usage(void)
{
    puts("Push-n-Catch v0.1 Copyright 2019 Vitaly Sinilin");
    puts("Transfers files between hosts in heterogenous IP network.\n");
    puts("Usage: to push:  push [/d] [/f] [@]peername files...");
    puts("       to catch: push /c [/d] [/f] [myname]\n");
    puts("The optional at sign (@) in front of peername in the push mode");
    puts("can be used to force broadcast peer discovery avoiding use of");
    puts("DNS resolver.\n");
    puts("Considering usually low performance of DOS machines, SHA-1");
    puts("digests used by the FPP protocol are disregarded by default");
    puts("in order to provide higher transfer rates. Use /d option to");
    puts("enable calculation and validation of digests.\n");
    puts("BEWARE! This program transfers files carelessly and absolutely");
    puts("unencrypted. It's meant to be used in a friendly environment.");
    puts("DO NOT USE IT IF YOU NEVER TAKE YOUR TIN FOIL HAT OFF.");
    exit(EXIT_FAILURE);
}

int main(int argc, const char *argv[])
{
    int catch_mode = 0;

    argv0 = argv[0];

    while (argc > 1) {
        if (argv[1][0] != '-' && argv[1][0] != '/')
            break;
        switch (argv[1][1]) {
            case '?':
            case 'h': usage(); break;
            case 'c': catch_mode = 1; break;
            case 'd': use_digests = 1; break;
            case 'f': use_force = 1; break;
            default: die("Unknown option %s", argv[1]);
        }
        argv++;
        argc--;
    }

    return catch_mode ? catch(argc, argv) : push(argc, argv);
}
