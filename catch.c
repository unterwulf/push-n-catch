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

static inline int send_short_msg(int sockfd, fpp_msg_t msg)
{
    return send_entire_check(sockfd, &msg, sizeof msg, 0);
}

static int receive_chunk(int sockfd, FILE *fp, off_t len, SHA1_CTX *sha1_ctx)
{
    int rv = 1;
    off_t nleft = len;

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
            SHA1Update(sha1_ctx, buf, nwritten);
        }
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
                err("Our SHA1 digest: %s", sha1_str(&digest));
                err("Peer SHA1 digest: %s", sha1_str(&peer_digest));
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

static int reject_file(int sockfd, const char *filename, fpp_off_t filelen)
{
    int rv = send_short_msg(sockfd, MSG_REJECT);
    if (!rv) {
        info("Rejected file %s (%llu bytes)",
             filename, (unsigned long long)filelen);
    }
    return rv;
}

static int accept_file(int sockfd, FILE *fp, const char *filename,
                       fpp_off_t filelen)
{
    int rv = send_short_msg(sockfd, MSG_ACCEPT);
    if (!rv) {
        SHA1_CTX sha1_ctx;
        info("Receiving file %s (%llu bytes)...",
             filename, (unsigned long long)filelen);
        SHA1Init(&sha1_ctx);
        rv = receive_chunk(sockfd, fp, filelen, &sha1_ctx);
    }
    return rv;
}

static int resume_negotiated_file(int sockfd, FILE *fp, const char *filename,
                                  fpp_off_t filelen, off_t pos)
{
    int rv;
    off_t nleft = pos;
    SHA1_CTX sha1_ctx;

    info("Calculating SHA1 of local %s...", filename);

    SHA1Init(&sha1_ctx);
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
        rv = EINTR;
    } else {
        struct sha1 peer_digest;
        rv = recv_entire_check(sockfd, &peer_digest, sizeof peer_digest, 0);

        if (!rv) {
            SHA1_CTX sha1_tmp_ctx = sha1_ctx;
            struct sha1 digest;
            SHA1Final((unsigned char *)&digest, &sha1_tmp_ctx);

            if (memcmp(&digest, &peer_digest, sizeof digest)) {
                info("Digests do not match");
                rv = send_short_msg(sockfd, MSG_NACK);
            } else {
                rv = send_short_msg(sockfd, MSG_ACK);
                if (!rv) {
                    off_t chunklen = filelen - pos;
                    if (chunklen > 0) {
                        info("Receiving continuation of file %s "
                             "(%llu bytes)...",
                             filename, (unsigned long long)chunklen);

                        /* C standard requires a call to a file position
                         * function when switching from reading to writing.
                         * Unless this is done, following fwrite fails
                         * on Windows. */
                        fseek(fp, 0L, SEEK_CUR);

                        rv = receive_chunk(sockfd, fp, chunklen, &sha1_ctx);
                    } else {
                        info("Digests match, nothing to receive");
                    }
                }
            }
        }
    }
    return rv;
}

static int resume_file(int sockfd, FILE *fp, const char *filename,
                       fpp_off_t filelen, off_t pos)
{
    struct {
        fpp_msg_t msg;
        fpp_off_t off;
    } __attribute__ ((packed)) rsp = { MSG_RESUME, hton_offset(pos) };

    int rv = send_entire_check(sockfd, &rsp, sizeof rsp, 0);
    if (!rv) {
        fpp_msg_t req;
        rv = recv_entire_check(sockfd, &req, sizeof req, 0);
        if (!rv) {
            if (req == MSG_ACCEPT) {
                rv = resume_negotiated_file(sockfd, fp, filename, filelen, pos);
            } else if (req == MSG_REJECT) {
                info("Peer doesn't want to append to an existing file");
            } else {
                err("Unexpected request");
                rv = 1;
            }
        }
    }
    return rv;
}

static int handle_push_request(int sockfd, const char *filename,
                               fpp_off_t filelen)
{
    int rv;
    struct stat sb;

    info("Push request of file %s (%llu bytes)", filename,
         (unsigned long long)filelen);

    rv = stat(filename, &sb);
    if (!rv) {
        if (S_ISREG(sb.st_mode)) {
            if ((fpp_off_t)sb.st_size <= filelen) {
                /* b in mode is important for Windows */
                FILE *fp = fopen(filename, "rb+");
                if (fp) {
                    rv = resume_file(sockfd, fp, filename, filelen, sb.st_size);
                    fclose(fp);
                } else {
                    info("Cannot open file %s for writing", filename);
                    rv = reject_file(sockfd, filename, filelen);
                }
            } else {
                info("Local file is bigger (%llu bytes)",
                     (unsigned long long)sb.st_size);
                rv = reject_file(sockfd, filename, filelen);
            }
        } else {
            err("Not a regular file %s", filename);
            rv = reject_file(sockfd, filename, filelen);
        }
    } else if (errno == ENOENT) {
        /* b in mode is important for Windows */
        FILE *fp = fopen(filename, "wb");
        if (fp) {
            rv = accept_file(sockfd, fp, filename, filelen);
            fclose(fp);
        } else {
            err("Cannot create file %s", filename);
            rv = reject_file(sockfd, filename, filelen);
        }
    } else {
        err("Cannot stat file %s", filename);
        rv = reject_file(sockfd, filename, filelen);
    }
    return rv;
}

static int handle_request(int sockfd)
{
    fpp_msg_t req;
    int rv = recv_entire(sockfd, &req, sizeof req, 0);
    if (rv == ECONNCLOSED) {
        ; /* It is ok if peer closes connection at this point. */
    } else if (rv != 0) {
        check_recv(rv);
    } else if (req != MSG_PUSH) {
        err("Unexpected request");
    } else {
        uint16_t namelen;
        rv = recv_entire_check(sockfd, &namelen, sizeof namelen, 0);
        if (!rv) {
            char *filename = NULL;
            namelen = ntohs(namelen);
            filename = malloc(namelen + 1);
            if (filename) {
                rv = recv_entire_check(sockfd, filename, namelen, 0);
                if (!rv) {
                    fpp_off_t filelen;
                    filename[namelen] = '\0';
                    rv = recv_entire_check(sockfd, &filelen, sizeof filelen, 0);
                    if (!rv) {
                        filelen = ntoh_offset(filelen);
                        sanitize_filename(filename);
                        rv = handle_push_request(sockfd, filename, filelen);
                    }
                }
                free(filename);
            } else {
                rv = 1; /* malloc error */
            }
        }
    }
    return rv;
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
