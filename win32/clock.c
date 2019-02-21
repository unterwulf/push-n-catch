#include "clock.h"
#include <windows.h>

uint32_t clock_get_monotonic(void)
{
    return GetTickCount();
}
