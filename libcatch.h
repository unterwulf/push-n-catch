#ifndef LIBCATCH_H
#define LIBCATCH_H

#include "platform.h"
#include <stdio.h>
#include <signal.h>

struct catch_context {
    char *filename;    /* application-provided buffer */
    size_t filenamesz; /* and its size */
    FILE *fp;
    off_t filepos;
    off_t filelen;
    Sock sk;
    int calc_digest;
    volatile sig_atomic_t *terminate;
    void (*on_stage_change)(const struct catch_context *ctx, int stage);
    void (*on_progress)(const struct catch_context *ctx, int stage);
    int (*confirm_file)(const struct catch_context *ctx);
};

enum catch_stage {
    CATCH_NEXT_FILE,
    CATCH_RECEIVE,
    CATCH_RESUME,
    CATCH_SHA1_CALC
};

int libcatch_handle_request(struct catch_context *ctx);

/* Application must define type Sock and implement these functions. */
// uint16_t htons(uint16_t hostshort);
// uint16_t ntohs(uint16_t netshort);
extern int get_filelen(const char *filename, off_t *filelen);
extern void sanitize_filename(char *filename);
extern int send_entire(Sock sk, const void *buf, size_t len);
extern int recv_entire(Sock sk, void *buf, size_t len);

#endif
