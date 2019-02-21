#ifndef SHA1UTIL_H
#define SHA1UTIL_H

#include <stdint.h>
#include <stdio.h>

#define SHA1_LEN 20

struct sha1 {
    uint8_t value[SHA1_LEN];
};

static inline char *sha1_str(const struct sha1 *hash)
{
    static char buf[SHA1_LEN*2 + 1];
    char *out = buf;
    size_t i;
    for (i = 0; i < SHA1_LEN; i++)
        out += sprintf(out, "%02x", hash->value[i]);
    return buf;
}

#endif
