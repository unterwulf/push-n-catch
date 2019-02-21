#ifndef NET_SYS_H
#define NET_SYS_H

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define closesocket(sockfd) close(sockfd)

#endif
