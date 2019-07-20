#include "common.h"
#include "dospush.h"
#include "fpp.h"
#include "libpush.h"
#include <tcp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static in_addr_t resolve_peername(const char *peername)
{
    in_addr_t peer_addr = INADDR_NONE;
    int i;

    /* Negative answers from DNS resolver can be annoyingly slow,
     * so the at sign before peername can be used to avoid using DNS to
     * resolve peername and start broadcast discovery immediately. */
    if (peername[0] != '@') {
        peer_addr = resolve_fn(peername, &is_int_pending);
        if (peer_addr)
            return peer_addr;
        peer_addr = INADDR_NONE;
    } else {
        peername++;
    }

    /* Otherwise discover peer using broadcast UDP request */
    if (!udp_open(&udp_sk, 0, INADDR_BROADCAST, CATCH_PORT, NULL))
        die("Cannot create UDP socket");
    sock_recv_init(&udp_sk, udp_skbuf, sizeof udp_skbuf); /* never fails */

    info("Discovering peers...");

    for (i = 0; i < 5 && peer_addr == INADDR_NONE && !terminate; i++)
    {
        long timeout = set_timeout(1);
        uint8_t req = DISCOVERY_VER;
        if (send_entire(&udp_sk, &req, sizeof req) != 0)
            die("Could not send discovery request");

        while (!chk_timeout(timeout) && peer_addr == INADDR_NONE) {
            in_addr_t disc_addr;
            char disc_rsp[PEERNAME_MAX+1];
            int disc_rsp_len;

            tcp_tick(&udp_sk);
            disc_rsp_len = sock_recv_from(&udp_sk, &disc_addr, NULL,
                                          &disc_rsp, sizeof disc_rsp, 0);
            if (disc_rsp_len) {
                size_t namelen = (uint8_t)disc_rsp[0];
                char *name = &disc_rsp[1];
                disc_addr = ntohl(disc_addr);

                if (namelen < disc_rsp_len) {
                    info("Peer %.*s found at %s", namelen, name,
                         in_addr_str(disc_addr));
                    if (strlen(peername) == namelen &&
                        !memcmp(name, peername, namelen))
                        peer_addr = disc_addr;
                }
            }
        }
    }

    sock_close(&udp_sk);
    if (peer_addr == INADDR_NONE)
        die("Peer %s wasn't located", peername);
    return peer_addr;
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
        info("Calculating SHA1 of initial %lu bytes of %s...",
             (unsigned long)ctx->fileoff, ctx->filename);
        break;
    case PUSH_RESUME:
        info("Resume sending of file %s from %lu (%lu bytes)",
             ctx->filename,
             (unsigned long)ctx->fileoff,
             (unsigned long)ctx->filelen);
        break;
    }
}

static void die_push(const struct push_context *ctx, const char *msg)
{
    err(msg);
    if (ctx->filepos > ctx->fileoff) {
        err("Transmission terminated at %lu of %lu bytes",
            (unsigned long)ctx->filepos,
            (unsigned long)ctx->filelen);
    }
    exit(EXIT_FAILURE);
}

static int push_file(tcp_Socket *sk, const char *pathname)
{
    int rv = 0;
    struct push_context ctx;
    ctx.terminate = &terminate;
    ctx.sk = sk;
    ctx.filename = basename(pathname);
    ctx.filelen = get_filelen_or_die(pathname);
    ctx.calc_digest = use_digests;
    ctx.on_stage_change = on_stage_change;
    ctx.fp = fopen(pathname, "rb"); /* b in mode is important for DOS */
    if (!ctx.fp)
        die_errno("Cannot open file %s", pathname);

    info("Sending file %s (%lu bytes)", pathname,
         (unsigned long)ctx.filelen);

    rv = libpush_push_file(&ctx);

    fclose(ctx.fp);

    switch (rv) {
    case 0:
        info("Transfer completed");
        break;
    case RV_REJECT:
        err("Peer rejected file %s", ctx.filename);
        break;
    case RV_NACK:
        err("Transfer completed, but peer reports that digests do NOT match");
        if (!ctx.calc_digest)
            err("Local digest wasn't calculated so it's an expected result");
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
        die_push(&ctx, "Ctrl/Break pressed");
    }

    return rv;
}

int push(int argc, const char *argv[])
{
    int ret = EXIT_SUCCESS;
    in_addr_t peer_addr;
    int i;

    if (argc < 3)
        usage(); /* does not return */

    init_wattcp();
    peer_addr = resolve_peername(argv[1]);
    info("Pushing to %s...", in_addr_str(peer_addr));

    if (!tcp_open(&tcp_sk, 0, peer_addr, CATCH_PORT, NULL))
        die("Could not connect to remote host");

    sock_wait_established(&tcp_sk, sock_delay, &is_int_pending, NULL);

    for (i = 2; i < argc && !terminate; i++)
        if (!push_file(&tcp_sk, argv[i]))
            ret = EXIT_FAILURE;

    sock_close(&tcp_sk);

    /* Not using sock_wait_closed() here to avoid TIME-WAIT timeout. */
    ip_timer_init(&tcp_sk, sock_delay);
    while (tcp_tick(&tcp_sk) && !tcp_time_wait(&tcp_sk)) {
        if (ip_timer_expired(&tcp_sk)) {
            err("Connection timed out");
            sock_abort(&tcp_sk);
            break;
        }
    }
    return ret;

sock_err:
    if (sockerr(&tcp_sk))
        err(sockerr(&tcp_sk));
    return EXIT_FAILURE;
}
