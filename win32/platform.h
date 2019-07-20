#ifndef PLATFORM_H
#define PLATFORM_H

#include <winsock2.h>
#include <sys/types.h>

typedef SOCKET Sock;

const char *basename(const char *pathname);
int get_filelen(const char *filename, off_t *filelen);
void sanitize_filename(char *filename);
int send_entire(Sock sk, const void *buf, size_t len);
int recv_entire(Sock sk, void *buf, size_t len);

#define to_off(fppoff) \
    (((fpp_off_t)(off_t)(fppoff) != (fppoff)) ? (off_t)(-1) : (off_t)(fppoff))

#define to_fpp_off(off) \
    (((off_t)(fpp_off_t)(off) != (off)) ? (fpp_off_t)(-1) : (fpp_off_t)(off))

void err_net(const char *fmt, ...);
void die_net(const char *fmt, ...);

#endif
