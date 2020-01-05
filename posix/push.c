#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "libpush.h"

static void signal_handler(int signum)
{
    UNUSED(signum);
    terminate = 1;
}

#if defined(__FreeBSD__) || defined(BSD) || defined(__APPLE__) || defined(__linux__)
# include <ifaddrs.h>
# include <net/if.h>
#else
#error Not implemented for this platform
#endif

struct in_addr *iterate_broadcast_addresses(struct in_addr *prev)
{
    static struct ifaddrs *ifap = NULL;
    static struct ifaddrs *pos = NULL;
    static struct in_addr *last = NULL;
    struct in_addr *next = NULL;

    if (!prev) {
        /* New round of iterations invalidates ongoing */
        if (ifap)
            freeifaddrs(ifap);

        if (getifaddrs(&ifap) != 0)
            ifap = NULL;

        pos = ifap;
    } else if (prev != last) {
        return NULL;
    }

    if (ifap) {
        if (pos) {
            for (; pos; pos = pos->ifa_next) {
                if ((pos->ifa_flags & IFF_BROADCAST) && pos->ifa_broadaddr
                        && pos->ifa_broadaddr->sa_family == AF_INET) {
                    last = &((struct sockaddr_in *)pos->ifa_broadaddr)->sin_addr;
                    next = last;
                    break;
                }
            }
            if (pos)
                pos = pos->ifa_next;
        } else {
           freeifaddrs(ifap);
           pos = ifap = NULL;
        }
    }

    return next;
}

static uint32_t clock_get_monotonic(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint32_t)(tp.tv_sec * 1000 + tp.tv_nsec / 1000000L);
}

static int discover_peer(int sockfd, const char *peername, struct in_addr *inp)
{
    uint8_t req = DISCOVERY_VER;
    uint32_t start_ms = clock_get_monotonic();
    struct in_addr *bcast_addr = NULL;
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(CATCH_PORT);

    while ((bcast_addr = iterate_broadcast_addresses(bcast_addr))) {
        sa.sin_addr = *bcast_addr;
        info("Send discovery to %s", inet_ntoa(sa.sin_addr));
        if (sendto(sockfd, (char *)&req, sizeof req, 0,
                    (struct sockaddr *)&sa, sizeof sa) != sizeof req)
            err_errno("sendto");
    }

    while (!terminate) {
        int retval;
        struct timeval tv;
        uint32_t elapsed_ms, remaining_ms;
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        /* Wait up to one second. */
        elapsed_ms = clock_get_monotonic() - start_ms;
        if (elapsed_ms >= 1000)
            break;
        remaining_ms = 1000 - elapsed_ms;
        tv.tv_sec = 0;
        tv.tv_usec = remaining_ms * 1000;

        retval = select(sockfd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1 && errno != EINTR)
            die_errno("select()");
        else if (retval > 0) {
            char buf[PEERNAME_MAX+2]; /* len byte + PEERNAME_MAX + nul */
            struct sockaddr_storage ss;
            socklen_t ss_len = sizeof ss;
            if (recvfrom(sockfd, buf, sizeof buf, 0,
                         (struct sockaddr *)&ss, &ss_len) > 0) {
                size_t namelen = (uint8_t)buf[0];
                char *name = &buf[1];
                name[namelen] = '\0';

                if (ss.ss_family == AF_INET) {
                    struct sockaddr_in *s = (struct sockaddr_in *)&ss;
                    info("Peer %s found at %s", name, inet_ntoa(s->sin_addr));
                    if (!strcmp(name, peername)) {
                        *inp = s->sin_addr;
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

static void resolve_peername(const char *peername, struct in_addr *inp)
{
    int sockfd;
    struct sockaddr_in sa;
    int optval = 1;
    int i;

    /* Negative answers from DNS resolver can be annoyingly slow,
     * so the at sign before peername can be used to avoid using DNS to
     * resolve peername and start broadcast discovery immediately. */
    if (peername[0] != '@') {
        struct hostent *hent = gethostbyname(peername);

        if (hent) {
            *inp = *(struct in_addr *)hent->h_addr;
            if (inp->s_addr != INADDR_NONE)
                return;
        }
    } else {
        peername++;
    }

    /* Otherwise discover peer using broadcast UDP request */
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0)
        die_errno("Cannot create UDP socket");

    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = INADDR_ANY;

    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (void *)&optval, sizeof optval) != 0)
        die_errno("setsockopt(SO_BROADCAST) failed");

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        die_errno("Cannot bind UDP socket to INADDR_ANY");

    info("Discovering peers...");
    inp->s_addr = INADDR_NONE;

    for (i = 0; i < 5 && !terminate; i++)
        if (discover_peer(sockfd, peername, inp))
            break;

    close(sockfd);

    if (terminate)
        die("Terminated");
    if (inp->s_addr == INADDR_NONE)
        die("Peer %s wasn't located", peername);
}

static off_t get_filelen_or_die(const char *pathname)
{
    off_t filelen = 0;
    int rv = get_filelen(pathname, &filelen);
    if (rv == RV_IOERROR)
        die_errno("Cannot stat file %s", pathname);
    else if (rv == RV_NOT_REGULAR_FILE)
        die("Not a regular file %s", pathname);
    else if (rv == RV_NOENT)
        die("File %s does not exist", pathname);

    return filelen;
}

static void on_stage_change(const struct push_context *ctx, int stage)
{
    switch (stage) {
    case PUSH_SHA1_CALC:
        info("Calculating SHA1 of initial %llu bytes of %s...",
             (unsigned long long)ctx->fileoff, ctx->filename);
        break;
    case PUSH_RESUME:
        info("Resume sending of file %s from %llu (%llu bytes)",
             ctx->filename,
             (unsigned long long)ctx->fileoff,
             (unsigned long long)ctx->filelen);
        break;
    }
}

static void die_push(const struct push_context *ctx, const char *msg)
{
    err(msg);
    if (ctx->filepos > ctx->fileoff) {
        err("Transmission terminated at %llu of %llu bytes",
            (unsigned long long)ctx->filepos,
            (unsigned long long)ctx->filelen);
    }
    exit(EXIT_FAILURE);
}

static int push_file(int sockfd, const char *pathname)
{
    struct push_context ctx;
    ctx.terminate = &terminate;
    ctx.sk = sockfd;
    ctx.filename = basename(pathname);
    ctx.filelen = get_filelen_or_die(pathname);
    ctx.fileoff = 0;
    ctx.calc_digest = 1;
    ctx.on_stage_change = on_stage_change;
    ctx.fp = fopen(pathname, "r");
    if (!ctx.fp)
        die_errno("Cannot open file %s", pathname);

    info("Sending file %s (%llu bytes)", pathname,
         (unsigned long long)ctx.filelen);

    int rv = libpush_push_file(&ctx);

    fclose(ctx.fp);

    switch (rv) {
    case 0:
        info("Transfer completed");
        break;
    case RV_REJECT:
        err("Peer rejected file %s", ctx.filename);
        break;
    case RV_NACK:
        info("Transfer completed, but peer reports that digests do NOT match");
        break;
    case RV_RESUME_NACK:
        err("Peer already has a different file %s (digests do not match)",
            ctx.filename);
        break;
    case RV_RESUME_ACK:
        info("Peer already has exactly the same file (digests match)");
        rv = 0;
        break;

    case RV_UNEXPECTED:
        die_push(&ctx, "Unexpected response");
    case RV_CONNCLOSED:
        die_push(&ctx, "Peer unexpectedly closed connection");
    case RV_IOERROR:
        die_push(&ctx, "Disk IO error");
    case RV_NETIOERROR:
        die_push(&ctx, "Network IO error");
    case RV_TERMINATED:
        die_push(&ctx, "Signal received");
    }

    return rv;
}

int main(int argc, const char *argv[])
{
    int ret = EXIT_SUCCESS;
    int i;
    int sockfd;
    struct sockaddr_in sa;

    if (argc < 3) {
        puts("usage: push [@]peername files...\n");
        puts("The optional at sign (@) in front of peername can be used");
        puts("to force broadcast peer discovery avoiding use of DNS resolver.\n");
        puts("BEWARE! This program pushes files carelessly and absolutely");
        puts("unencrypted. DO NOT USE IT IF YOU CAN.");
        exit(EXIT_FAILURE);
    }

    /* We count on interruptable syscalls, so we avoid using signal() here. */
    struct sigaction sigact = {};
    sigact.sa_handler = signal_handler;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
        die_errno("Cannot create TCP socket");

    sa.sin_family = AF_INET;
    sa.sin_port = htons(CATCH_PORT);
    resolve_peername(argv[1], &sa.sin_addr);

    info("Pushing to %s", inet_ntoa(sa.sin_addr));

    if (connect(sockfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        die_errno("Cannot connect to remote host");

    for (i = 2; i < argc && !terminate; i++)
        if (push_file(sockfd, argv[i]) != 0)
            ret = EXIT_FAILURE;

    close(sockfd);
    return ret;
}
