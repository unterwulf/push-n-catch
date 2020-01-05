#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "fpp.h"
#include "libpush.h"
#include "sha1.h"
#include "sha1util.h"

#define BLOCKSIZE 512

static int push_chunk(struct push_context *ctx, SHA1_CTX *sha1_ctx)
{
    int rv = 0;
    fpp_msg_t rsp;
    struct sha1 digest;
    off_t nleft = ctx->filelen - ctx->filepos;

    while (nleft > 0) {
        unsigned char buf[BLOCKSIZE];
        size_t chunk = (nleft > BLOCKSIZE) ? BLOCKSIZE : nleft;

        if (fread(buf, 1, chunk, ctx->fp) != chunk)
            return RV_IOERROR;

        rv = send_entire(ctx->sk, buf, chunk);
        if (rv)
            return rv;

        if (ctx->calc_digest)
            SHA1Update(sha1_ctx, buf, chunk);

        nleft -= chunk;
        ctx->filepos += chunk;

        if (*ctx->terminate)
            return RV_TERMINATED;
    }

    /* Once transmission of file is completed, we must send our digest,
     * so the peer can ensure that the transmission was correct. */
    if (ctx->calc_digest)
        SHA1Final((unsigned char *)&digest, sha1_ctx);
    else
        memset(&digest, '\0', sizeof digest);

    rv = send_entire(ctx->sk, &digest, sizeof digest);
    if (rv)
        return rv;

    rv = recv_entire(ctx->sk, &rsp, sizeof rsp);
    if (rv)
        return rv;

    if (rsp == MSG_NACK)
        rv = RV_NACK;
    else if (rsp == MSG_ACK)
        rv = 0;
    else
        rv = RV_UNEXPECTED;

    return rv;
}

static int send_push_request(struct push_context *ctx)
{
    fpp_msg_t msg = MSG_PUSH;
    uint16_t namelen = strlen(ctx->filename);
    uint16_t be_namelen = htons(namelen);
    fpp_off_t be_fileoff = hton_offset(to_fpp_off(ctx->fileoff));
    fpp_off_t be_filelen = hton_offset(to_fpp_off(ctx->filelen));
    int rv;

    rv = send_entire(ctx->sk, &msg, sizeof msg);
    if (rv)
        return rv;
    rv = send_entire(ctx->sk, &be_namelen, sizeof be_namelen);
    if (rv)
        return rv;
    rv = send_entire(ctx->sk, ctx->filename, namelen);
    if (rv)
        return rv;
    rv = send_entire(ctx->sk, &be_fileoff, sizeof be_fileoff);
    if (rv)
        return rv;
    rv = send_entire(ctx->sk, &be_filelen, sizeof be_filelen);
    return rv;
}

int libpush_push_file(struct push_context *ctx)
{
    fpp_msg_t msg;
    int rv;

    ctx->filepos = 0;

    rv = send_push_request(ctx);
    if (rv)
        return rv;

    rv = recv_entire(ctx->sk, &msg, sizeof msg);
    if (rv)
        return rv;

    if (msg == MSG_REJECT) {
        rv = RV_REJECT;
    } else if (msg == MSG_ACCEPT) {
        SHA1_CTX sha1_ctx;
        SHA1Init(&sha1_ctx);

        if (ctx->fileoff) {
            if (ctx->calc_digest) {
                /* Calculate our digest */
                off_t nleft = ctx->fileoff;

                if (ctx->on_stage_change)
                    ctx->on_stage_change(ctx, PUSH_SHA1_CALC);

                while (nleft > 0) {
                    unsigned char buf[BLOCKSIZE];
                    size_t chunk = (nleft > BLOCKSIZE) ? BLOCKSIZE : nleft;
                    if (fread(buf, 1, chunk, ctx->fp) != chunk) {
                        return RV_IOERROR;
                    } else {
                        SHA1Update(&sha1_ctx, buf, chunk);
                        nleft -= chunk;
                        ctx->filepos += chunk;
                    }
                    if (*ctx->terminate)
                        return RV_TERMINATED;
                }
            } else {
                ctx->filepos = ctx->fileoff;
            }

            /* Send our digest */ {
                struct sha1 digest;
                if (ctx->calc_digest) {
                    SHA1_CTX tmp_sha1_ctx = sha1_ctx;
                    SHA1Final((unsigned char *)&digest, &tmp_sha1_ctx);
                } else {
                    memset(&digest, '\0', sizeof digest);
                }

                rv = send_entire(ctx->sk, &digest, sizeof digest);
                if (rv)
                    return rv;
            }

            rv = recv_entire(ctx->sk, &msg, sizeof msg);
            if (rv)
                return rv;

            if (msg == MSG_NACK) {
                return RV_RESUME_NACK;
            } else if (msg == MSG_ACK && ctx->fileoff == ctx->filelen) {
                return RV_RESUME_ACK;
            } else if (msg != MSG_ACK) {
                return RV_UNEXPECTED;
            }
        }

        if (ctx->fileoff && ctx->on_stage_change)
            ctx->on_stage_change(ctx, PUSH_RESUME);

        rv = push_chunk(ctx, &sha1_ctx);
    } else if (msg == MSG_REJECT_OFFSET && ctx->fileoff == 0) {
        /* Peer indicated that it already has our file. */
        fpp_off_t fpp_off;
        off_t fileoff;

        rv = recv_entire(ctx->sk, &fpp_off, sizeof fpp_off);
        if (rv)
            return rv;

        fileoff = to_off(ntoh_offset(fpp_off));

        if (fileoff == -1 || fileoff == 0 || fileoff > ctx->filelen)
            return RV_UNEXPECTED;

        ctx->fileoff = fileoff;
        rv = libpush_push_file(ctx);
    } else if (msg == MSG_ACK && ctx->fileoff == 0 && ctx->filelen == 0) {
        rv = RV_RESUME_ACK;
    } else {
        rv = RV_UNEXPECTED;
    }
    return rv;
}
