#ifndef CLOCK_H
#define CLOCK_H

#include <stdint.h>

/* Returns monotonically increasing number of milliseconds.
 * Absolute value has no particular meaning defined. */
uint32_t clock_get_monotonic(void);

#endif
