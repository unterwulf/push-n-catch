#include "common.h"
#include "dospush.h"
#include "fpp.h"
#include "libcatch.h"
#include "platform.h"
#include <tcp.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define SKBUF_SIZE 8192

#if 0
            off_t chunklen = to_off(filelen) - sb.st_size;
            struct sha1 digest, peer_digest;

            if (use_digests) {
                SHA1_CTX sha1_tmp_ctx;
                off_t nleft = sb.st_size;

                info("Calculating SHA1 of local %s...", filename);

                while (nleft > 0 && !watcbroke) {
                    unsigned char buf[BLOCKSIZE];
                    size_t chunk = (nleft > BLOCKSIZE) ? BLOCKSIZE : nleft;
                    if (fread(buf, 1, chunk, fp) != chunk) {
                        die("Read error");
                    } else {
                        SHA1Update(&sha1_ctx, buf, chunk);
                        nleft -= chunk;
                    }
                }

                if (watcbroke)
                    die("Terminated");

                sha1_tmp_ctx = sha1_ctx;
                SHA1Final((unsigned char *)&digest, &sha1_tmp_ctx);
            }
#endif

static void on_stage_change(const struct catch_context *ctx, int stage)
{
    switch (stage) {
    case CATCH_NEXT_FILE:
        info("Push request of file %s (%lu bytes)", ctx->filename,
             (unsigned long)ctx->filelen);
        break;
    case CATCH_RECEIVE:
        info("Receiving file %s (%lu bytes)...",
             ctx->filename, (unsigned long)ctx->filelen);
        break;
    case CATCH_SHA1_CALC:
        info("Calculating SHA1 of local %s...", ctx->filename);
        break;
    case CATCH_RESUME:
        info("Receiving continuation of file %s (%lu bytes)...",
             ctx->filename, (unsigned long)(ctx->filelen - ctx->filepos));
        break;
    }
}

static int handle_connection(tcp_Socket *sk)
{
    int rv = 0;
    int close_connection = 0;
    char filename[4096];
    struct catch_context ctx;

    memset(&ctx, '\0', sizeof ctx);
    ctx.terminate = &terminate;
    ctx.on_stage_change = on_stage_change;
    ctx.sk = sk;
    ctx.filename = filename;
    ctx.filenamesz = sizeof filename;
    ctx.calc_digest = use_digests;

    while (!close_connection) {
        rv = libcatch_handle_request(&ctx);

        switch (rv) {
        case 0:
            info("Transfer completed");
            break;
        case RV_COMPLETED_DIGEST_MISMATCH:
            err("Transfer completed (digests do NOT match)");
            break;
        case RV_DIGEST_MATCH:
            info("Already have this file (digests match)");
            break;
        case RV_SIZE_MATCH:
            info("Already have this file (same size, digests not verified)");
            break;
        case RV_REJECT:
            info("Peer does not want to append to an existing file");
            break;
        case RV_LOCAL_BIGGER:
            info("Rejected file %s (%lu bytes), local version is bigger",
                 ctx.filename, (unsigned long)ctx.filelen);
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
                err("Transmission aborted, only %lu of %lu bytes received",
                    (unsigned long)ctx.filepos,
                    (unsigned long)ctx.filelen);
                break;
            case RV_IOERROR:
                err("Disk IO error while processing file %s", ctx.filename);
                break;
            }
        }
    }

    return rv;
}

int catch(int argc, const char *argv[])
{
    static udp_Socket udp_out_sk;
    static char tcp_skbuf[SKBUF_SIZE];

    struct {
        uint8_t len;
        char name[PEERNAME_MAX];
    } disc_rsp = { 3, "dos" };

    if (argc > 2) {
        usage(); /* does not return */
    } else if (argc == 2) {
        size_t namelen = strlen(argv[1]);
        if (namelen > PEERNAME_MAX)
            die("Peername %s too long", argv[1]);
        disc_rsp.len = namelen;
        memcpy(disc_rsp.name, argv[1], disc_rsp.len);
    }

    init_wattcp();
    if (!udp_open(&udp_sk, CATCH_PORT, INADDR_BROADCAST, 0, NULL))
        die("Cannot create UDP socket");
    sock_recv_init(&udp_sk, udp_skbuf, sizeof udp_skbuf); /* never fails */

    info("Initialized with peername %.*s (use Ctrl/Break to terminate)",
         disc_rsp.len, disc_rsp.name);

    while (!terminate) {
        if (!tcp_listen(&tcp_sk, CATCH_PORT, INADDR_ANY, 0, NULL, 0))
            die("Could not create TCP socket");
        sock_setbuf(&tcp_sk, tcp_skbuf, sizeof tcp_skbuf);

        while (!terminate) {
            uint8_t disc_req;
            in_addr_t peer_addr;
            unsigned short peer_port;

            tcp_tick(NULL);

            if (sock_recv_from(&udp_sk, &peer_addr, &peer_port,
                               &disc_req, sizeof disc_req, 0)) {
                if (disc_req == DISCOVERY_VER) {
                    peer_addr = ntohl(peer_addr);
                    peer_port = ntohs(peer_port);
                    if (udp_open(&udp_out_sk, CATCH_PORT,
                                 peer_addr, peer_port, NULL)) {
                        info("Discovery from %s", in_addr_str(peer_addr));
                        sock_write(&udp_out_sk, &disc_rsp, disc_rsp.len + 1);
                        sock_close(&udp_out_sk);
                    } else {
                        err("Cannot create UDP socket to reply to discovery");
                    }
                }
            }

            if (sock_established(&tcp_sk)) {
                handle_connection(&tcp_sk);
                break;
            }
        }

        sock_close(&tcp_sk);
        sock_wait_closed(&tcp_sk, sock_delay, &is_int_pending, NULL);
sock_err:
    }

    sock_close(&udp_sk);
    return EXIT_SUCCESS;
}
