#ifndef FPP_H
#define FPP_H

/* File push protocol definitions */

#include <stdint.h>

#define MSG_PUSH            0
#define MSG_FORCED_PUSH     1
#define MSG_ACCEPT          2
#define MSG_REJECT          3
#define MSG_RESUME          4
#define MSG_ACK             5
#define MSG_NACK            6

typedef uint8_t fpp_msg_t;
typedef uint64_t fpp_off_t;

#endif
