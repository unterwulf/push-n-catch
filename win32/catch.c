#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <winsock2.h>

#include "common.h"
#include "libcatch.h"

static char myname[PEERNAME_MAX+1];
static int allow_forced;

extern void handle_discovery(int fd, const char *name);

static void signal_handler(int signum)
{
    UNUSED(signum);
    terminate = 1;
}

static void on_stage_change(const struct catch_context *ctx, int stage)
{
    switch (stage) {
    case CATCH_NEXT_FILE:
        if (ctx->forced) {
            info("Forced push request of file %s (%llu bytes)", ctx->filename,
                 (unsigned long long)ctx->filelen);
        } else {
            info("Push request of file %s (%llu bytes)", ctx->filename,
                 (unsigned long long)ctx->filelen);
        }
        break;
    case CATCH_RECEIVE:
        if (!ctx->fileoff) {
            info("Receiving file %s (%llu bytes)...",
                 ctx->filename, (unsigned long long)ctx->filelen);
        } else {
            info("Receiving continuation of file %s (%lu bytes)...",
                 ctx->filename,
                 (unsigned long long)(ctx->filelen - ctx->fileoff));
        }
        break;
    case CATCH_SHA1_CALC:
        info("Calculating SHA1 of local %s...", ctx->filename);
        break;
    }
}

static int handle_connection(int sockfd)
{
    int rv = 0;
    int close_connection = 0;
    char filename[4096];
    struct catch_context ctx;

    memset(&ctx, '\0', sizeof ctx);
    ctx.terminate = &terminate;
    ctx.on_stage_change = on_stage_change;
    ctx.sk = sockfd;
    ctx.filename = filename;
    ctx.filenamesz = sizeof filename;
    ctx.calc_digest = 1;
    ctx.allow_forced = allow_forced;

    while (!close_connection) {
        rv = libcatch_handle_request(&ctx);

        switch (rv) {
        case 0:
            info("Transfer completed");
            break;
        case RV_COMPLETED_DIGEST_MISMATCH:
            err("Transfer completed (digests do NOT match)");
        case RV_OFFSET:
            break;
        case RV_DIGEST_MATCH:
            info("Already have this file (digests match)");
            break;
        case RV_SIZE_MATCH:
            info("Already have this file (same size, digests not verified)");
            break;
        case RV_REJECT:
            info("Rejected forced push of file %s (%llu bytes)",
                 ctx.filename, (unsigned long long)ctx.filelen);
            break;
        case RV_LOCAL_BIGGER:
            info("Rejected file %s (%llu bytes), local version is bigger",
                 ctx.filename, (unsigned long long)ctx.filelen);
            break;
        case RV_NOT_REGULAR_FILE:
            err("Not a regular file %s", ctx.filename);
            break;
        case RV_NACK:
            info("Digests do not match");
            break;
        case RV_TOOBIG:
            info("Rejected too big file %s", ctx.filename);
            break;

        /* All other return values mean the connection should be closed. */
        default:
            close_connection = 1;
            switch (rv) {
            case RV_UNEXPECTED:
                err("Unexpected request");
                break;
            case RV_TERMINATED:
                err("Transmission aborted, only %llu of %llu bytes received",
                    (unsigned long long)ctx.filepos,
                    (unsigned long long)ctx.filelen);
                break;
            case RV_NETIOERROR:
                err("Network IO error while processing file %s", ctx.filename);
                break;
            case RV_IOERROR:
                err("Disk IO error while processing file %s", ctx.filename);
                break;
            }
        }
    }

    return rv;
}

int main(int argc, const char *argv[])
{
    int tcpfd, udpfd;
    struct sockaddr_in sa;

    signal(SIGINT, &signal_handler);
    signal(SIGTERM, &signal_handler);

    WSADATA wsaData;
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0)
        die("WSAStartup failed with error: %d", err);

    if (argc > 1 && !strcmp(argv[1], "-f")) {
        allow_forced = 1;
        argc--;
        argv++;
    }

    if (argc == 2) {
        size_t namelen = strlen(argv[1]);
        if (namelen > PEERNAME_MAX)
            die("Peername %s too long", argv[1]);
        strcpy(myname, argv[1]);
    } else {
        if (gethostname(myname, sizeof myname) != 0)
            die_net("Cannot determine hostname");
        myname[sizeof myname - 1] = '\0';
    }

    tcpfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcpfd < 0)
        die_net("Cannot create TCP socket");

    sa.sin_family = AF_INET;
    sa.sin_port = htons(CATCH_PORT);
    sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(tcpfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        die_net("Cannot bind to TCP port %hu", CATCH_PORT);

    if (listen(tcpfd, 1) != 0)
        die_net("Cannot listen to TCP socket");

    udpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpfd < 0)
        die_net("Cannot create UDP socket");

    if (bind(udpfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        die_net("Cannot bind to UDP port %hu", CATCH_PORT);

    info("Initialized with peername %s", myname);

    while (!terminate) {
        fd_set rfds;
        int retval;

        FD_ZERO(&rfds);
        FD_SET(tcpfd, &rfds);
        FD_SET(udpfd, &rfds);

        retval = select(udpfd + 1, &rfds, NULL, NULL, NULL);

        if (retval == -1 && errno != EINTR)
            die_net("select()");
        else if (retval > 0) {
            if (FD_ISSET(udpfd, &rfds)) {
                handle_discovery(udpfd, myname);
            } else {
                int sa_len = sizeof sa;
                int connfd = accept(tcpfd, (struct sockaddr *)&sa, &sa_len);
                if (connfd >= 0) {
                    int rv = handle_connection(connfd);

                    /* If something wrong happened and we have to actively close
                     * the connection, let us reset it. Otherwise, it will end
                     * up in the TIME-WAIT state, which will make consequent run
                     * of catch impossible until the timeout exceeds. */
                    if (rv != RV_CONNCLOSED) {
                        struct linger linger = { 1, 0 };
                        (void)setsockopt(connfd, SOL_SOCKET, SO_LINGER,
                                         (const char *)&linger, sizeof linger);
                    }
                    closesocket(connfd);
                } else {
                    err_net("Cannot accept TCP connection");
                }
            }
        }
    }
    closesocket(udpfd);
    closesocket(tcpfd);

    return EXIT_SUCCESS;
}
