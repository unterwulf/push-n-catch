#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "fpp.h"
#include "libcatch.h"
#include "sha1.h"
#include "sha1util.h"

#define BLOCKSIZE 512

static int receive_chunk(struct catch_context *ctx, SHA1_CTX *sha1_ctx)
{
    int rv = 0;
    off_t nleft = ctx->filelen - ctx->filepos;

    while (nleft && !*ctx->terminate) {
        unsigned char buf[BLOCKSIZE];
        size_t chunk = (nleft > BLOCKSIZE) ? BLOCKSIZE : nleft;
        rv = recv_entire(ctx->sk, (char *)buf, chunk);
        if (!rv) {
            if (fwrite(buf, 1, chunk, ctx->fp) != chunk)
                return RV_IOERROR;
            nleft -= chunk;
            ctx->filepos += chunk;
            if (ctx->calc_digest)
                SHA1Update(sha1_ctx, buf, chunk);
            if (ctx->on_progress)
                ctx->on_progress(ctx, CATCH_RECEIVE);
        } else {
            return rv;
        }
    }

    if (nleft > 0) {
        rv = RV_TERMINATED;
    } else {
        struct sha1 digest, peer_digest;

        SHA1Final((unsigned char *)&digest, sha1_ctx);
        rv = recv_entire(ctx->sk, &peer_digest, sizeof peer_digest);
        if (!rv) {
            if (ctx->calc_digest && memcmp(&digest, &peer_digest, sizeof digest)) {
                rv = send_short_msg(ctx->sk, MSG_NACK);
                if (!rv)
                    rv = RV_COMPLETED_DIGEST_MISMATCH;
            } else {
                rv = send_short_msg(ctx->sk, MSG_ACK);
            }
        }
    }

    return rv;
}

static int reject_file(struct catch_context *ctx)
{
    return send_short_msg(ctx->sk, MSG_REJECT);
}

static int accept_file(struct catch_context *ctx)
{
    int rv = send_short_msg(ctx->sk, MSG_ACCEPT);
    if (!rv) {
        SHA1_CTX sha1_ctx;
        SHA1Init(&sha1_ctx);

        if (ctx->on_stage_change)
            ctx->on_stage_change(ctx, CATCH_RECEIVE);

        rv = receive_chunk(ctx, &sha1_ctx);
    }
    return rv;
}

static int resume_negotiated_file(struct catch_context *ctx)
{
    int rv;
    struct sha1 peer_digest;
    SHA1_CTX sha1_ctx;
    SHA1Init(&sha1_ctx);

    if (ctx->calc_digest) {
        off_t nleft = ctx->filepos;

        if (ctx->on_stage_change)
            ctx->on_stage_change(ctx, CATCH_SHA1_CALC);

        ctx->filepos = 0;

        while (nleft > 0) {
            unsigned char buf[BLOCKSIZE];
            size_t chunk = (nleft > BLOCKSIZE) ? BLOCKSIZE : nleft;

            if (fread(buf, 1, chunk, ctx->fp) != chunk)
                return RV_IOERROR;

            SHA1Update(&sha1_ctx, buf, chunk);
            nleft -= chunk;
            ctx->filepos += chunk;

            if (ctx->on_progress)
                ctx->on_progress(ctx, CATCH_SHA1_CALC);

            if (*ctx->terminate)
                return RV_TERMINATED;
        }
    }

    rv = recv_entire(ctx->sk, &peer_digest, sizeof peer_digest);

    if (!rv) {
        SHA1_CTX sha1_tmp_ctx = sha1_ctx;
        struct sha1 digest;
        SHA1Final((unsigned char *)&digest, &sha1_tmp_ctx);

        if (ctx->calc_digest && memcmp(&digest, &peer_digest, sizeof digest)) {
            rv = send_short_msg(ctx->sk, MSG_NACK);
            if (!rv)
                rv = RV_NACK;
        } else {
            rv = send_short_msg(ctx->sk, MSG_ACK);
            if (!rv) {
                off_t chunklen = ctx->filelen - ctx->filepos;
                if (chunklen > 0) {
                    if (ctx->on_stage_change)
                        ctx->on_stage_change(ctx, CATCH_RESUME);

                    /* C standard requires a call to a file position
                     * function when switching from reading to writing.
                     * Unless this is done, the following fwrite call
                     * fails at least on Windows. */
                    fseek(ctx->fp, 0L, SEEK_CUR);

                    rv = receive_chunk(ctx, &sha1_ctx);
                } else {
                    rv = (ctx->calc_digest) ? RV_DIGEST_MATCH : RV_SIZE_MATCH;
                }
            }
        }
    }

    return rv;
}

static int resume_file(struct catch_context *ctx)
{
    int rv = 0;
    fpp_msg_t msg = MSG_RESUME;
    fpp_off_t off = hton_offset(to_fpp_off(ctx->filepos));
    char buf[sizeof msg + sizeof off];
    memcpy(buf, &msg, sizeof msg);
    memcpy(buf + sizeof msg, &off, sizeof off);

    rv = send_entire(ctx->sk, buf, sizeof buf);
    if (!rv) {
        fpp_msg_t req;
        rv = recv_entire(ctx->sk, &req, sizeof req);
        if (!rv) {
            if (req == MSG_ACCEPT) {
                rv = resume_negotiated_file(ctx);
            } else if (req == MSG_REJECT) {
                rv = RV_REJECT;
            } else {
                rv = RV_UNEXPECTED;
            }
        }
    }
    return rv;
}

static int handle_push_request(struct catch_context *ctx)
{
    int rv;
    uint16_t namelen;
    fpp_off_t fpp_off;
    off_t filelen;

    rv = recv_entire(ctx->sk, &namelen, sizeof namelen);
    if (rv)
        return rv;

    namelen = ntohs(namelen);
    if (namelen >= ctx->filenamesz)
        return RV_UNEXPECTED;

    rv = recv_entire(ctx->sk, ctx->filename, namelen);
    if (rv)
        return rv;

    ctx->filename[namelen] = '\0';
    sanitize_filename(ctx->filename);

    rv = recv_entire(ctx->sk, &fpp_off, sizeof fpp_off);
    if (rv)
        return rv;

    ctx->filelen = to_off(ntoh_offset(fpp_off));

    if (ctx->filelen == -1) {
        rv = reject_file(ctx);
        return (rv) ? rv : RV_TOOBIG;
    }

    if (ctx->on_stage_change)
        ctx->on_stage_change(ctx, CATCH_NEXT_FILE);

    rv = get_filelen(ctx->filename, &filelen);
    if (rv == RV_NOENT) {
        /* b in mode is important for Windows. */
        ctx->fp = fopen(ctx->filename, "wb");
        if (ctx->fp) {
            ctx->filepos = 0;
            rv = accept_file(ctx);
            fclose(ctx->fp);
        } else {
            rv = reject_file(ctx);
            if (!rv)
                rv = RV_IOERROR;
        }
    } else if (rv == 0) {
        if (filelen <= ctx->filelen) {
            /* b in mode is important for Windows. */
            ctx->fp = fopen(ctx->filename, "rb+");
            if (ctx->fp) {
                ctx->filepos = filelen;
                rv = resume_file(ctx);
                fclose(ctx->fp);
            } else {
                rv = reject_file(ctx);
                if (!rv)
                    rv = RV_IOERROR;
            }
        } else {
            rv = reject_file(ctx);
            if (!rv)
                rv = RV_LOCAL_BIGGER;
        }
    } else {
        int rv2 = reject_file(ctx);
        if (rv2)
            rv = rv2;
    }
    return rv;
}

int libcatch_handle_request(struct catch_context *ctx)
{
    fpp_msg_t req;
    int rv = recv_entire(ctx->sk, &req, sizeof req);
    if (rv)
        return rv;

    if (req == MSG_PUSH) {
        rv = handle_push_request(ctx);
    } else {
        rv = RV_UNEXPECTED;
    }

    if (rv == RV_CONNCLOSED)
        rv = RV_TERMINATED;

    return rv;
}
