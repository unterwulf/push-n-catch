#include "clock.h"
#include <stdint.h>
#include <time.h>

uint32_t clock_get_monotonic(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (uint32_t)(tp.tv_sec * 1000 + tp.tv_nsec / 1000000L);
}
