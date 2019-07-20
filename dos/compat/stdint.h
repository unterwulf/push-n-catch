#ifndef STDINT_H
#define STDINT_H

/* Borland C++ does not provide this C99 standard header. */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
typedef struct { unsigned long word[2]; } uint64_t;

#endif
