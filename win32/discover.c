#include <string.h>
#include <sys/types.h>
#include <winsock2.h>

#include "common.h"

void handle_discovery(int fd, const char *myname)
{
    uint8_t req;
    struct sockaddr_storage ss;
    int ss_len = sizeof ss;
    size_t namelen = strlen(myname);
    char buf[PEERNAME_MAX+1];
    if (namelen > PEERNAME_MAX)
        namelen = PEERNAME_MAX;
    buf[0] = namelen;
    memcpy(&buf[1], myname, namelen);
    if (recvfrom(fd, (char *)&req, 1, 0, (struct sockaddr *)&ss, &ss_len) == 1) {
        if (req == DISCOVERY_VER)
            sendto(fd, buf, namelen + 1, 0, (struct sockaddr *)&ss, ss_len);
    }
}
