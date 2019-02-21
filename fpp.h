#ifndef FPP_H
#define FPP_H

/* File push protocol definitions */

#include <stdint.h>

/* 01234567
 * TTTFFFFF
 */

#define MSG_PUSH   0
#define MSG_ACCEPT 1
#define MSG_REJECT 2

#define MSG_FLAGS_OFFSET 1
#define MSG_FLAGS_ALL    2

#define IS_MSG_TYPE(msg, type) \
    ((msg)>>5 == (type))

#define HAS_MSG_FLAG(msg, flag) \
    (((msg) & 0x1F) & (flag))

#define FPP_MSG(type, flags) \
    ((((type) & 0x7)<<5) | ((flags) & 0x1F))

typedef uint64_t fpp_off_t;

#endif
