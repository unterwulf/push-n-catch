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

static int accept_file(struct catch_context *ctx)
{
    int rv;
    struct sha1 peer_digest;
    SHA1_CTX sha1_ctx;
    SHA1Init(&sha1_ctx);

    rv = send_short_msg(ctx->sk, MSG_ACCEPT);
    if (rv)
        return rv;

    ctx->filepos = 0;

    if (ctx->fileoff) {
        if (ctx->calc_digest) {
            off_t nleft = ctx->fileoff;

            if (ctx->on_stage_change)
                ctx->on_stage_change(ctx, CATCH_SHA1_CALC);

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
        } else {
            ctx->filepos = ctx->fileoff;
        }

        rv = recv_entire(ctx->sk, &peer_digest, sizeof peer_digest);
        if (rv)
            return rv;

        if (ctx->calc_digest) {
            SHA1_CTX sha1_tmp_ctx = sha1_ctx;
            struct sha1 digest;
            SHA1Final((unsigned char *)&digest, &sha1_tmp_ctx);

            if (memcmp(&digest, &peer_digest, sizeof digest)) {
                rv = send_short_msg(ctx->sk, MSG_NACK);
                return (rv) ? rv : RV_NACK;
            }
        }

        rv = send_short_msg(ctx->sk, MSG_ACK);
        if (rv)
            return rv;
    }

    if (!ctx->filelen || ctx->filepos < ctx->filelen) {
        if (ctx->on_stage_change)
            ctx->on_stage_change(ctx, CATCH_RECEIVE);

        /* C standard requires a call to a file position function when
         * switching from reading to writing. Unless this is done, the
         * following fwrite call fails at least on Windows. */
        fseek(ctx->fp, 0L, SEEK_CUR);

        rv = receive_chunk(ctx, &sha1_ctx);
    } else {
        rv = (ctx->calc_digest) ? RV_DIGEST_MATCH : RV_SIZE_MATCH;
    }

    return rv;
}

static int reject_file(struct catch_context *ctx)
{
    return send_short_msg(ctx->sk, MSG_REJECT);
}

static int reject_file_offset(struct catch_context *ctx, off_t offset)
{
    fpp_msg_t msg = MSG_REJECT_OFFSET;
    fpp_off_t off = hton_offset(to_fpp_off(offset));
    char buf[sizeof msg + sizeof off];
    memcpy(buf, &msg, sizeof msg);
    memcpy(buf + sizeof msg, &off, sizeof off);

    return send_entire(ctx->sk, buf, sizeof buf);
}

static int handle_push_request(struct catch_context *ctx)
{
    int rv;
    uint16_t namelen;
    fpp_off_t fpp_off;
    off_t filelen;
    int new_file = 1;

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

    ctx->fileoff = to_off(ntoh_offset(fpp_off));

    if (ctx->fileoff == -1) {
        rv = reject_file(ctx);
        return (rv) ? rv : RV_TOOBIG;
    }

    rv = recv_entire(ctx->sk, &fpp_off, sizeof fpp_off);
    if (rv)
        return rv;

    ctx->filelen = to_off(ntoh_offset(fpp_off));

    if (ctx->filelen == -1) {
        rv = reject_file(ctx);
        return (rv) ? rv : RV_TOOBIG;
    }

    if (ctx->fileoff > ctx->filelen) {
        rv = reject_file(ctx);
        return (rv) ? rv : RV_UNEXPECTED;
    }

    rv = get_filelen(ctx->filename, &filelen);
    if (rv == RV_NOENT) {
        if (ctx->fileoff) {
            rv = reject_file_offset(ctx, 0);
            return (rv) ? rv : RV_OFFSET;
        }
    } else if (rv == 0) {
        if (filelen == 0 && ctx->fileoff == 0 && ctx->filelen == 0) {
            rv = send_short_msg(ctx->sk, MSG_ACK);
            return (rv) ? rv : RV_DIGEST_MATCH;
        } else if (filelen > ctx->filelen) {
            rv = reject_file(ctx);
            return (rv) ? rv : RV_LOCAL_BIGGER;
        } else if (filelen != ctx->fileoff) {
            rv = reject_file_offset(ctx, filelen);
            return (rv) ? rv : RV_OFFSET;
        }
        new_file = 0;
    } else {
        int rv2 = reject_file(ctx);
        return (rv2) ? rv2 : rv;
    }

    if (ctx->on_stage_change)
        ctx->on_stage_change(ctx, CATCH_NEXT_FILE);

    /* b in mode is important for Windows. */
    ctx->fp = fopen(ctx->filename, new_file ? "wb" : "rb+");
    if (ctx->fp) {
        rv = accept_file(ctx);
        fclose(ctx->fp);
    } else {
        rv = reject_file(ctx);
        if (!rv)
            rv = RV_IOERROR;
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
