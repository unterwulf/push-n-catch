#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "clock.h"
#include "common.h"
#include "fpp.h"
#include "net.h"
#include "sha1.h"
#include "sha1util.h"

#if defined(__FreeBSD__) || defined(BSD) || defined(__APPLE__) || defined(__linux__)
# define USE_GETIFADDRS 1
# include <ifaddrs.h>
# include <net/if.h>
#elif defined(_WIN32)
# include <iphlpapi.h>
#endif

#define BLOCKSIZE 512

static void signal_handler(int signum)
{
    UNUSED(signum);
    terminate = 1;
}

static void xsend(int sockfd, const void *buf, size_t len, int flags)
{
    if (send_entire_check(sockfd, buf, len, flags) != 0)
        exit(EXIT_FAILURE);
}

static void xrecv(int sockfd, void *buf, size_t len, int flags)
{
    if (recv_entire_check(sockfd, buf, len, flags) != 0)
        exit(EXIT_FAILURE);
}

static void sendto_all_ifaces(int sockfd, const void *buf, size_t len, int flags)
{
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(CATCH_PORT);

#if defined(USE_GETIFADDRS)
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) == 0) {
        struct ifaddrs *p = ifap;
        for (; p; p = p->ifa_next) {
            if ((p->ifa_flags & IFF_BROADCAST) && p->ifa_broadaddr
                && p->ifa_broadaddr->sa_family == AF_INET) {
                sa.sin_addr = ((struct sockaddr_in *)p->ifa_broadaddr)->sin_addr;
                info("Send discovery to %s", inet_ntoa(sa.sin_addr));
                if (sendto(sockfd, buf, len, flags,
                           (struct sockaddr *)&sa, sizeof sa) != (ssize_t)len)
                    neterr("sendto");
            }
        }
        freeifaddrs(ifap);
    }
#elif defined(_WIN32)
    // Adapted from example code at http://msdn2.microsoft.com/en-us/library/aa365917.aspx
    // Now get Windows' IPv4 addresses table.  Once again, we gotta call GetIpAddrTable()
    // multiple times in order to deal with potential race conditions properly.
    MIB_IPADDRTABLE *ipTable = NULL;
    {
        ULONG bufLen = 0;
        for (int i = 0; i < 5; i++) {
            DWORD ipRet = GetIpAddrTable(ipTable, &bufLen, 0);
            if (ipRet == ERROR_INSUFFICIENT_BUFFER) {
                free(ipTable);  // in case we had previously allocated it
                ipTable = malloc(bufLen);
            } else if (ipRet == NO_ERROR) {
                break;
            } else {
                free(ipTable);
                ipTable = NULL;
                break;
            }
        }
    }

    if (ipTable) {
        for (DWORD i = 0; i < ipTable->dwNumEntries; i++) {
            const MIB_IPADDRROW *row = &(ipTable->table[i]);
            uint32_t addr      = ntohl(row->dwAddr);
            uint32_t netmask   = ntohl(row->dwMask);
            uint32_t bcastaddr = addr | ~netmask;
            sa.sin_addr.s_addr = htonl(bcastaddr);
            info("Send discovery to %s", inet_ntoa(sa.sin_addr));
            if (sendto(sockfd, buf, len, flags,
                        (struct sockaddr *)&sa, sizeof sa) != (ssize_t)len)
                neterr("sendto");
        }

        free(ipTable);
    }
#endif
}

static int discover_peer(int sockfd, const char *peername, struct in_addr *inp)
{
    uint8_t req = DISCOVERY_VER;
    uint32_t start_ms = clock_get_monotonic();

    sendto_all_ifaces(sockfd, &req, sizeof req, 0);

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
            die_neterr("select()");
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
        die_neterr("Cannot create UDP socket");

    sa.sin_family = AF_INET;
    sa.sin_port = 0;
    sa.sin_addr.s_addr = INADDR_ANY;

    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, (void *)&optval, sizeof optval) != 0)
        die_neterr("setsockopt(SO_BROADCAST) failed");

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        die_neterr("Cannot bind UDP socket to INADDR_ANY");

    info("Discovering peers...");
    inp->s_addr = INADDR_NONE;

    for (i = 0; i < 5 && !terminate; i++)
        if (discover_peer(sockfd, peername, inp))
            break;

    closesocket(sockfd);

    if (terminate)
        die("Terminated");
    if (inp->s_addr == INADDR_NONE)
        die("Peer %s wasn't located", peername);
}

static const char *basename(const char *pathname)
{
    char *base = strrchr(pathname, PATHSEP);
    return base ? (base + 1) : pathname;
}

static int push_chunk(int sockfd, FILE *fp, off_t total, SHA1_CTX *sha1_ctx)
{
    fpp_msg_t rsp;
    struct sha1 digest;
    off_t nleft = total;

    while (nleft > 0 && !terminate) {
        unsigned char buf[BLOCKSIZE];
        size_t chunk = (nleft > BLOCKSIZE) ? BLOCKSIZE : nleft;
        if (fread(buf, 1, chunk, fp) != chunk) {
            err("Read error");
            break;
        } else {
            ssize_t nsent = send(sockfd, (char *)buf, chunk, 0);
            if (nsent == -1) {
                if (errno == EINTR) {
                    nsent = 0;
                } else if (errno == ECONNRESET) {
                    err("Peer unexpectedly closed the connection");
                    break;
                }
            } else {
                SHA1Update(sha1_ctx, buf, nsent);
                nleft -= nsent;
            }
        }
    }

    if (nleft > 0) {
        err("Transmission terminated at %llu of %llu bytes",
            (unsigned long long)(total - nleft), (unsigned long long)total);
        return 0;
    }

    /* Once transmission of file is completed, we must send our digest,
     * so the peer can ensure that the transmission was correct. */
    SHA1Final((unsigned char *)&digest, sha1_ctx);
    xsend(sockfd, &digest, sizeof digest, 0);
    xrecv(sockfd, &rsp, sizeof rsp, 0);

    if (rsp == MSG_NACK) {
        err("Transfer completed, but peer reports that digests do NOT match");
        return 0;
    } else if (rsp == MSG_ACK) {
        info("Transfer completed");
    } else {
        die("Unexpected response");
    }
    return 1;
}

void send_push_request(int sockfd, const char *filename, off_t filelen)
{
    fpp_msg_t msg = MSG_PUSH;
    uint16_t namelen = strlen(filename);
    uint16_t be_namelen = htons(namelen);
    fpp_off_t be_filelen = hton_offset(filelen);

    xsend(sockfd, &msg, sizeof msg, 0);
    xsend(sockfd, &be_namelen, sizeof be_namelen, 0);
    xsend(sockfd, filename, namelen, 0);
    xsend(sockfd, &be_filelen, sizeof be_filelen, 0);
}

off_t get_file_len(const char *pathname)
{
    struct stat sb;
    if (stat(pathname, &sb) != 0)
        die_errno("Cannot stat file %s", pathname);

    if (!S_ISREG(sb.st_mode))
        die("Not a regular file %s", pathname);

    return sb.st_size;
}

static int push_file(int sockfd, const char *pathname)
{
    fpp_msg_t msg;
    const char *filename = basename(pathname);
    off_t filelen = get_file_len(pathname);
    int ret = 1;

    FILE *fp = fopen(pathname, "rb"); /* b in mode is important for Windows */
    if (!fp)
        die_errno("Cannot open file %s", pathname);

    send_push_request(sockfd, filename, filelen);

    xrecv(sockfd, &msg, sizeof msg, 0);

    if (msg == MSG_REJECT) {
        err("Peer rejected file %s", filename);
        ret = 0;
    } else if (msg == MSG_ACCEPT) {
        SHA1_CTX sha1_ctx;
        SHA1Init(&sha1_ctx);

        info("Sending file %s (%llu bytes)", pathname,
             (unsigned long long)filelen);

        ret = push_chunk(sockfd, fp, filelen, &sha1_ctx);
    } else if (msg == MSG_RESUME) {
        /* Peer indicated that it already has our file */
        fpp_off_t peerfilelen;
        SHA1_CTX sha1_ctx;
        SHA1Init(&sha1_ctx);

        xrecv(sockfd, &peerfilelen, sizeof peerfilelen, 0);
        peerfilelen = ntoh_offset(peerfilelen);

        if (peerfilelen > (fpp_off_t)filelen)
            die("Unexpected response");

        msg = MSG_ACCEPT;
        xsend(sockfd, &msg, sizeof msg, 0);

        /* Calculate our digest */ {
            off_t nleft = peerfilelen;
            info("Calculating SHA1 of initial %llu bytes of %s...",
                 (unsigned long long)nleft, filename);

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

            if (terminate)
                die("Terminated");
        }

        /* Send our digest */ {
            struct sha1 digest;
            SHA1_CTX tmp_sha1_ctx = sha1_ctx;
            SHA1Final((unsigned char *)&digest, &tmp_sha1_ctx);
            xsend(sockfd, &digest, sizeof digest, 0);
        }

        xrecv(sockfd, &msg, sizeof msg, 0);
        if (msg == MSG_NACK) {
            err("Peer already has a different file %s (digests do not match)",
                filename);
            ret = 0;
        } else if (msg == MSG_ACK) {
            if ((fpp_off_t)filelen == peerfilelen) {
                info("Peer already has exactly the same file (digests match)");
            } else {
                info("Resume sending of file %s from %llu (%llu bytes)",
                     pathname,
                     (unsigned long long)peerfilelen,
                     (unsigned long long)filelen);
                ret = push_chunk(sockfd, fp, filelen - peerfilelen, &sha1_ctx);
            }
        } else {
            die("Unexpected response");
        }
    } else {
        die("Unexpected response");
    }
    fclose(fp);
    return ret;
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

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
        die_neterr("Cannot create TCP socket");

    sa.sin_family = AF_INET;
    sa.sin_port = htons(CATCH_PORT);
    resolve_peername(argv[1], &sa.sin_addr);

    info("Pushing to %s", inet_ntoa(sa.sin_addr));

    if (connect(sockfd, (struct sockaddr *)&sa, sizeof sa) != 0)
        die_neterr("Cannot connect to remote host");

    for (i = 2; i < argc && !terminate; i++)
        if (!push_file(sockfd, argv[i]))
            ret = EXIT_FAILURE;

    closesocket(sockfd);
    return ret;
}