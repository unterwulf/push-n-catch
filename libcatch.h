#ifndef LIBCATCH_H
#define LIBCATCH_H

#include <sys/types.h>

struct libcatch_ctx {
    void (*report_progress)(off_t npassed, off_t ntotal);
    int (*confirm_file)(const char *filename, off_t filelen);
    int (*is_termination_requested)(void);
};

void libcatch_handle_discovery(int sockfd, const char *myname);
int libcatch_handle_request(struct libcatch_ctx *ctx, int sockfd);

#endif
