#ifndef PLATFORM_H
#define PLATFORM_H

#include <tcp.h>
#include <stdint.h>

#if defined(__BORLANDC__) || defined(__TURBOC__)
typedef long off_t;
#endif

/* Internet address.  */
typedef uint32_t in_addr_t;

/* Address to accept any incoming messages.  */
#define INADDR_ANY              ((in_addr_t) 0x00000000)
/* Address to send to all hosts.  */
#define INADDR_BROADCAST        ((in_addr_t) 0xffffffff)
/* Address indicating an error return.  */
#define INADDR_NONE             ((in_addr_t) 0xffffffff)

const char *in_addr_str(in_addr_t addr);

typedef tcp_Socket *Sock;

const char *basename(const char *pathname);
int get_filelen(const char *filename, off_t *filelen);
void sanitize_filename(char *filename);
int send_entire(Sock sk, const void *buf, size_t len);
int recv_entire(Sock sk, void *buf, size_t len);

#define to_off(fpp_off) (((fpp_off).word[1] != 0) ? -1 : (fpp_off).word[0])
fpp_off_t to_fpp_off(off_t off);

#endif
