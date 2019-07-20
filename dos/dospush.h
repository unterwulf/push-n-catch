#ifndef DOSPUSH_H
#define DOSPUSH_H

#include <tcp.h>

#define UDP_BACKLOG_SIZE 4096

extern int use_digests;
extern tcp_Socket tcp_sk;
extern udp_Socket udp_sk;
extern char udp_skbuf[UDP_BACKLOG_SIZE];

void usage(void);
void init_wattcp(void);
int is_int_pending(void *sock);

int push(int argc, const char *argv[]);
int catch(int argc, const char *argv[]);

#endif
