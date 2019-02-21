#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "fpp.h"
#include "net.h"
#include "sha1.h"
#include "sha1util.h"

#define BLOCKSIZE 512

char myname[PEERNAME_MAX+1];

static void signal_handler(int signum)
{
    UNUSED(signum);
    terminate = 1;
}

static void sanitize_filename(char *filename)
{
    char *p = filename;
    for (; *p; p++) {
        if (*p == PATHSEP)
            *p = '_';
    }
}

static void handle_discovery(int fd)
{
    uint8_t req;
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof ss;
    size_t namelen = strlen(myname);
    char buf[PEERNAME_MAX+1];
    buf[0] = namelen;
    memcpy(&buf[1], myname, namelen);
    if (recvfrom(fd, (char *)&req, 1, 0, (struct sockaddr *)&ss, &ss_len) == 1) {
        if (req == DISCOVERY_VER)
            sendto(fd, buf, namelen + 1, 0, (struct sockaddr *)&ss, ss_len);
    }
}

int handle_request(int sockfd)
{
    FILE *fp = NULL;
    char *filename = NULL;
    uint16_t namelen;
    fpp_off_t filelen;
    struct stat sb;
    uint8_t msg_type = MSG_ACCEPT;
    uint8_t msg;
    off_t nleft, ntotal;
    int flags = 0;
    int rc;
    SHA1_CTX sha1_ctx;
    struct sha1 digest;

    SHA1Init(&sha1_ctx);

    rc = recv_entire(sockfd, &msg, sizeof msg, 0);
    /* It's ok if peer closes connection at this point */
    if (rc == ECONNCLOSED || check_recv(rc) != 0)
        return rc;

    if (!IS_MSG_TYPE(msg, MSG_PUSH)) {
        err("Unexpected request");
        return 0;
    }

    if (recv_entire_check(sockfd, &namelen, sizeof namelen, 0) != 0)
        return 0;

    namelen = ntohs(namelen);
    filename = malloc(namelen + 1);
    if (!filename)
        return 0;

    if (recv_entire_check(sockfd, filename, namelen, 0) != 0)
        goto fail;

    filename[namelen] = '\0';

    if (recv_entire_check(sockfd, &filelen, sizeof filelen, 0) != 0)
        goto fail;

    filelen = ntoh_offset(filelen);
    ntotal = filelen;

    sanitize_filename(filename);

    info("Push request of file %s (%llu bytes)", filename, filelen);

    rc = stat(filename, &sb);
    if (rc != 0 && errno != ENOENT) {
        err("Cannot stat file %s", filename);
        msg_type = MSG_REJECT;
    } else if (rc == 0) {
        if (!S_ISREG(sb.st_mode)) {
            err("Not a regular file %s", filename);
            msg_type = MSG_REJECT;
        } else {
            flags |= MSG_FLAGS_OFFSET;
            if ((fpp_off_t)sb.st_size <= filelen) {
                ntotal -= sb.st_size;
                /* b in mode is important for Windows */
                fp = fopen(filename, "rb+");
                if (!fp) {
                    info("Cannot open file %s for writing", filename);
                    msg_type = MSG_REJECT;
                }
            } else {
                info("Local file is bigger (%llu bytes)",
                     (unsigned long long)sb.st_size);
                msg_type = MSG_REJECT;
            }
        }
    } else { /* ENOENT */
        /* b in mode is important for Windows */
        fp = fopen(filename, "wb");
        if (!fp) {
            info("Cannot create file %s", filename);
            msg_type = MSG_REJECT;
        }
    }

    msg = FPP_MSG(msg_type, flags);
    if (send_entire_check(sockfd, &msg, sizeof msg, 0) != 0)
        goto fail;

    if (flags & MSG_FLAGS_OFFSET) {
        fpp_off_t off = hton_offset(sb.st_size);
        if (send_entire_check(sockfd, &off, sizeof off, 0) != 0)
            goto fail;

        if (msg_type == MSG_ACCEPT) {
            SHA1_CTX sha1_tmp_ctx;
            off_t nleft = sb.st_size;

            info("Calculating SHA1 of local %s...", filename);

            while (nleft > 0 && !terminate) {
                unsigned char buf[BLOCKSIZE];
                size_t chunk = (nleft > BLOCKSIZE) ? BLOCKSIZE : nleft;
                if (fread(buf, 1, chunk, fp) != chunk) {
                    die("Read error");
                } else {
                    SHA1Update(&sha1_ctx, buf, chunk);
                    nleft -= chunk;
                }
            }
            if (terminate) {
                // TODO
            }

            /* POSIX requires a call to a file position function when
             * switching from reading to writing. Unless this is done
             * following fwrite will fail on Windows. */
            fseek(fp, 0L, SEEK_CUR);

            sha1_tmp_ctx = sha1_ctx;
            SHA1Final((unsigned char *)&digest, &sha1_tmp_ctx);
            if (send_entire_check(sockfd, &digest, sizeof digest, 0) != 0)
                goto fail;

            /* At this point peer may found that digests differ
             * and decide not to push remaining part of the file.
             * In the latter case it has two options:
             * - either to close connection if no more files are to be
             *   sent;
             * - reply with MSG_REJECT and start pushing next file. */
            rc = recv_entire(sockfd, &msg, sizeof msg, 0);
            /* It's ok if peer closes connection at this point */
            if (rc == 0 || !check_recv(rc) || IS_MSG_TYPE(msg, MSG_REJECT)) {
                info("Peer abandoned attempt to append %llu bytes to file %s",
                     (unsigned long long)(filelen - sb.st_size), filename);
                return 0;
            }

            /* Otherwise it has to reply with MSG_ACCEPT and start
             * sending remaining part of the file. */
            if (!IS_MSG_TYPE(msg, MSG_ACCEPT))
                return 0;
        }
    }

    if (msg_type == MSG_REJECT) {
        info("Rejected incoming file %s (%llu bytes)", filename, filelen);
        return 1;
    }

    nleft = ntotal;

    if (nleft) {
        if (flags & MSG_FLAGS_OFFSET) {
            info("Receiving continuation of file %s (%llu bytes)...",
                 filename, (unsigned long long)nleft);
        } else {
            info("Receiving file %s (%llu bytes)...",
                 filename, (unsigned long long)nleft);
        }

        while (nleft && !terminate) {
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
                SHA1Update(&sha1_ctx, buf, nwritten);
            }
        }

        if (nleft) {
            err("Transmission aborted, only %llu of %llu bytes received",
                (unsigned long long)(ntotal - nleft), (unsigned long long)ntotal);
        }
    }

    if (!nleft) {
        SHA1Final((unsigned char *)&digest, &sha1_ctx);
        if (send_entire_check(sockfd, &digest, sizeof digest, 0) != 0)
            goto fail;

        if (ntotal)
            info("Transfer completed");
    }
    free(filename);
    fclose(fp);
    return !nleft ? 1 : 0;

fail:
    if (fp)
        fclose(fp);
    free(filename);
    return 0;
}

int main(int argc, const char *argv[])
{
    int tcpfd, udpfd;
    struct sockaddr_in sa;

#ifdef _WIN32
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#else
    /* We count on interruptable syscalls, so we avoid using signal() here */
    struct sigaction sigact = {};
    sigact.sa_handler = signal_handler;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
#endif

    init_netlib();

    if (argc == 2) {
        size_t namelen = strlen(argv[1]);
        if (namelen > PEERNAME_MAX)
            die("Peername %s too long", argv[1]);
        strcpy(myname, argv[1]);
    } else {
        if (gethostname(myname, sizeof myname) != 0)
            die_neterr("Cannot determine hostname");
        myname[sizeof myname - 1] = '\0';
    }

    info("Initialized with peername %s", myname);

    tcpfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcpfd < 0)
        die_neterr("Cannot create TCP socket");

    sa.sin_family = AF_INET;
    sa.sin_port = htons(CATCH_PORT);
    sa.sin_addr.s_addr = INADDR_ANY;

    if (bind(tcpfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        die_neterr("Cannot bind to TCP port %hu", CATCH_PORT);

    if (listen(tcpfd, 1) != 0)
        die_neterr("Cannot listen to TCP socket");

    udpfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpfd < 0)
        die_neterr("Cannot create UDP socket");

    if (bind(udpfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        die_neterr("Cannot bind to UDP port %hu", CATCH_PORT);

    while (!terminate) {
        fd_set rfds;
        int retval;

        FD_ZERO(&rfds);
        FD_SET(tcpfd, &rfds);
        FD_SET(udpfd, &rfds);

        retval = select(udpfd + 1, &rfds, NULL, NULL, NULL);

        if (retval == -1 && errno != EINTR)
            die_neterr("select()");
        else if (retval > 0) {
            if (FD_ISSET(udpfd, &rfds)) {
                handle_discovery(udpfd);
            } else {
                socklen_t sa_len = sizeof sa;
                int connfd = accept(tcpfd, (struct sockaddr *)&sa, &sa_len);
                if (connfd >= 0) {
                    while (handle_request(connfd) == 0)
                        ;
                    closesocket(connfd);
                } else {
                    neterr("Cannot accept TCP connection");
                }
            }
        }
    }
    closesocket(udpfd);
    closesocket(tcpfd);

    return 0;
}
