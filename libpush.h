#ifndef LIBPUSH_H
#define LIBPUSH_H

#include "platform.h"
#include <stdio.h>
#include <signal.h>

struct push_context {
    const char *filename;
    FILE *fp;
    off_t fileoff;
    off_t filepos;
    off_t filelen;
    Sock sk;
    int calc_digest;
    int forced;
    volatile sig_atomic_t *terminate;
    void (*on_stage_change)(const struct push_context *ctx, int stage);
};

enum push_stage {
    PUSH_SHA1_CALC,
    PUSH_RESUME
};

int libpush_push_file(struct push_context *ctx);

/* The application must provide the following as functions or macros. */

/* Convert fpp_off_t to off_t, return -1 on overflow. */
/* off_t to_off(fpp_off_t off); */

/* Convert off_t to fpp_off_t, return (fpp_off_t)(-1) on overflow. */
/* fpp_off_t to_fpp_off(off_t off); */

#endif
