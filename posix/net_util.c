#include "net.h"
#include <stddef.h>

#if defined(__FreeBSD__) || defined(BSD) || defined(__APPLE__) || defined(__linux__)
# include <ifaddrs.h>
# include <net/if.h>
#else
#error Not implemented for this platform
#endif

struct in_addr *iterate_broadcast_addresses(struct in_addr *prev)
{
    static struct ifaddrs *ifap = NULL;
    static struct ifaddrs *pos = NULL;
    static struct in_addr *last = NULL;
    struct in_addr *next = NULL;

    if (!prev) {
        /* New round of iterations invalidates ongoing */
        if (ifap)
            freeifaddrs(ifap);

        if (getifaddrs(&ifap) != 0)
            ifap = NULL;

        pos = ifap;
    } else if (prev != last) {
        return NULL;
    }

    if (ifap) {
        if (pos) {
            for (; pos; pos = pos->ifa_next) {
                if ((pos->ifa_flags & IFF_BROADCAST) && pos->ifa_broadaddr
                        && pos->ifa_broadaddr->sa_family == AF_INET) {
                    last = &((struct sockaddr_in *)pos->ifa_broadaddr)->sin_addr;
                    next = last;
                    break;
                }
            }
            if (pos)
                pos = pos->ifa_next;
        } else {
           freeifaddrs(ifap);
           pos = ifap = NULL;
        }
    }

    return next;
}
