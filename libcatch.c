#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libcatch.h"
#include "common.h"
#include "fpp.h"
#include "net.h"
#include "sha1.h"
#include "sha1util.h"

#define BLOCKSIZE 512

static void sanitize_filename(char *filename)
{
    char *p = filename;
    for (; *p; p++) {
        if (*p == PATHSEP)
            *p = '_';
    }
}

static inline int send_short_msg(int sockfd, fpp_msg_t msg)
{
    return send_entire_check(sockfd, &msg, sizeof msg, 0);
}

void libcatch_handle_discovery(int sockfd, const char *myname)
{
    uint8_t req;
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof ss;
    size_t namelen = strlen(myname);
    char buf[PEERNAME_MAX+1];
    if (namelen > PEERNAME_MAX)
        namelen = PEERNAME_MAX;
    buf[0] = namelen;
    memcpy(&buf[1], myname, namelen);
    if (recvfrom(sockfd, (char *)&req, 1, 0, (struct sockaddr *)&ss, &ss_len) == 1) {
        if (req == DISCOVERY_VER)
            sendto(sockfd, buf, namelen + 1, 0, (struct sockaddr *)&ss, ss_len);
    }
}

static int receive_chunk(struct libcatch_ctx *ctx, int sockfd,
                         FILE *fp, off_t len, SHA1_CTX *sha1_ctx)
{
    int rv = 1;
    off_t nleft = len;

    while (nleft && !ctx->is_termination_requested()) {
        unsigned char buf[BLOCKSIZE];
        ssize_t chunk = (nleft > BLOCKSIZE) ? BLOCKSIZE : nleft;
        ssize_t nreceived = recv(sockfd, (char *)buf, chunk, 0);
        if (nreceived == -1 && errno == EINTR) {
            /* try again */;
        } else if (nreceived <= 0) {
            if (!nreceived)
                err("Peer unexpectedly closed connection");
            break; /* not terminate = 1; */
        } else {
            size_t nwritten = fwrite(buf, 1, nreceived, fp);
            nleft -= nwritten;
            if (nwritten != (size_t)nreceived) {
                err("Write error");
                break; /* not terminate = 1; */
            }
            SHA1Update(sha1_ctx, buf, nwritten);
        }
        if (ctx->report_progress)
            ctx->report_progress(len - nleft, len);
    }

    if (nleft > 0) {
        err("Transmission aborted, only %llu of %llu bytes received",
            (unsigned long long)(len - nleft), (unsigned long long)len);
    } else {
        struct sha1 digest, peer_digest;

        SHA1Final((unsigned char *)&digest, sha1_ctx);
        rv = recv_entire_check(sockfd, &peer_digest, sizeof peer_digest, 0);
        if (!rv) {
            if (memcmp(&digest, &peer_digest, sizeof digest)) {
                err("Our SHA1 digest: %s", sha1_str(&digest).value);
                err("Peer SHA1 digest: %s", sha1_str(&peer_digest).value);
                err("Transfer completed (digests do NOT match)");
                rv = send_short_msg(sockfd, MSG_NACK);
            } else {
                info("Transfer completed");
                rv = send_short_msg(sockfd, MSG_ACK);
            }
        }
    }

    return rv;
}

int libcatch_handle_request(struct libcatch_ctx *ctx, int sockfd)
{
    FILE *fp = NULL;
    char *filename = NULL;
    uint16_t namelen;
    fpp_off_t filelen;
    struct stat sb;
    fpp_msg_t msg;
    int ret = 1;
    int rc;
    SHA1_CTX sha1_ctx;

    SHA1Init(&sha1_ctx);

    rc = recv_entire(sockfd, &msg, sizeof msg, 0);
    /* It's ok if peer closes connection at this point */
    if (rc == ECONNCLOSED || !check_recv(rc))
        return rc;

    if (msg != MSG_PUSH) {
        err("Unexpected request");
        return EINVAL;
    }

    if (recv_entire_check(sockfd, &namelen, sizeof namelen, 0) != 0)
        return 1;

    namelen = ntohs(namelen);
    filename = malloc(namelen + 1);
    if (!filename)
        return 1;

    if (recv_entire_check(sockfd, filename, namelen, 0) != 0)
        goto fail;

    filename[namelen] = '\0';

    if (recv_entire_check(sockfd, &filelen, sizeof filelen, 0) != 0)
        goto fail;

    filelen = ntoh_offset(filelen);

    sanitize_filename(filename);

    info("Push request of file %s (%llu bytes)", filename,
         (unsigned long long)filelen);

    if (!ctx->confirm_file || ctx->confirm_file(filename, filelen)) {
        rc = stat(filename, &sb);
        if (rc != 0 && errno != ENOENT) {
            err("Cannot stat file %s", filename);
            msg = MSG_REJECT;
        } else if (rc == 0) {
            if (!S_ISREG(sb.st_mode)) {
                err("Not a regular file %s", filename);
                msg = MSG_REJECT;
            } else {
                if ((fpp_off_t)sb.st_size <= filelen) {
                    /* b in mode is important for Windows */
                    fp = fopen(filename, "rb+");
                    if (!fp) {
                        info("Cannot open file %s for writing", filename);
                        msg = MSG_REJECT;
                    } else {
                        msg = MSG_RESUME;
                    }
                } else {
                    info("Local file is bigger (%llu bytes)",
                         (unsigned long long)sb.st_size);
                    msg = MSG_REJECT;
                }
            }
        } else { /* ENOENT */
            /* b in mode is important for Windows */
            fp = fopen(filename, "wb");
            if (!fp) {
                info("Cannot create file %s", filename);
                msg = MSG_REJECT;
            }
        }
    } else {
        msg = MSG_REJECT;
    }

    if (send_entire_check(sockfd, &msg, sizeof msg, 0) != 0)
        goto fail;

    if (msg == MSG_REJECT) {
        info("Rejected file %s (%llu bytes)",
             filename, (unsigned long long)filelen);
    } else if (msg == MSG_ACCEPT) {
        info("Receiving file %s (%llu bytes)...",
             filename, (unsigned long long)filelen);
        ret = receive_chunk(ctx, sockfd, fp, filelen, &sha1_ctx);
    } else if (msg == MSG_RESUME) {
        fpp_off_t off = hton_offset(sb.st_size);
        if (send_entire_check(sockfd, &off, sizeof off, 0) != 0)
            goto fail;

        if (recv_entire_check(sockfd, &msg, sizeof msg, 0) != 0)
            goto fail;

        if (msg == MSG_REJECT) {
            info("Peer doesn't want to append to an existing file");
        } else if (msg == MSG_ACCEPT) {
            SHA1_CTX sha1_tmp_ctx;
            off_t chunklen = filelen - sb.st_size;
            off_t nleft = sb.st_size;
            struct sha1 digest, peer_digest;

            info("Calculating SHA1 of local %s...", filename);

            while (nleft > 0 && !ctx->is_termination_requested()) {
                unsigned char buf[BLOCKSIZE];
                size_t chunk = (nleft > BLOCKSIZE) ? BLOCKSIZE : nleft;
                if (fread(buf, 1, chunk, fp) != chunk) {
                    die("Read error");
                } else {
                    SHA1Update(&sha1_ctx, buf, chunk);
                    nleft -= chunk;
                }
            }

            if (ctx->is_termination_requested())
                die("Terminated");

            /* C standard requires a call to a file position function when
             * switching from reading to writing. Unless this is done,
             * following fwrite fails at least on Windows. */
            fseek(fp, 0L, SEEK_CUR);

            sha1_tmp_ctx = sha1_ctx;
            SHA1Final((unsigned char *)&digest, &sha1_tmp_ctx);
            if (recv_entire_check(sockfd, &peer_digest, sizeof peer_digest, 0) != 0)
                goto fail;

            if (memcmp(&digest, &peer_digest, sizeof digest)) {
                msg = MSG_NACK;
                info("Digest do not match");
            } else {
                msg = MSG_ACK;
            }
            if (send_entire_check(sockfd, &msg, sizeof msg, 0) != 0)
                goto fail;

            if (msg == MSG_ACK) {
                if (chunklen > 0) {
                    info("Receiving continuation of file %s (%llu bytes)...",
                         filename, (unsigned long long)chunklen);

                    ret = receive_chunk(ctx, sockfd, fp, chunklen, &sha1_ctx);
                } else {
                    info("Digests match, nothing to receive");
                }
            }
        } else {
            die("Unexpected response");
        }
    }

    if (fp)
        fclose(fp);
    free(filename);
    return ret;

fail:
    if (fp)
        fclose(fp);
    free(filename);
    return 1;
}
