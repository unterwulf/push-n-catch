#include "net.h"
#include <stddef.h>
#include <iphlpapi.h>

struct in_addr *iterate_broadcast_addresses(struct in_addr *prev)
{
    static MIB_IPADDRTABLE *ipTable = NULL;
    static DWORD pos;
    static struct in_addr last;
    struct in_addr *next = NULL;

    if (!prev) {
        /* New round of iterations invalidates ongoing */
        if (ipTable) {
            free(ipTable);
            ipTable = NULL;
            pos = 0;
        }

        // Adapted from example code at http://msdn2.microsoft.com/en-us/library/aa365917.aspx
        // Now get Windows' IPv4 addresses table.  Once again, we gotta call GetIpAddrTable()
        // multiple times in order to deal with potential race conditions properly.
        ULONG bufLen = 0;
        for (int i = 0; i < 5; i++) {
            DWORD ipRet = GetIpAddrTable(ipTable, &bufLen, 0);
            if (ipRet == ERROR_INSUFFICIENT_BUFFER) {
                free(ipTable);  // in case we had previously allocated it
                ipTable = malloc(bufLen);
            } else if (ipRet == NO_ERROR) {
                break;
            } else {
                free(ipTable);
                ipTable = NULL;
                break;
            }
        }
    } else if (prev != &last) {
        return NULL;
    }

    if (ipTable) {
        if (pos < ipTable->dwNumEntries) {
            const MIB_IPADDRROW *row = &(ipTable->table[pos]);
            DWORD addr      = ntohl(row->dwAddr);
            DWORD netmask   = ntohl(row->dwMask);
            DWORD bcastaddr = addr | ~netmask;
            last.s_addr = htonl(bcastaddr);
            next = &last;
            pos++;
        } else {
            free(ipTable);
            ipTable = NULL;
            pos = 0;
        }
    }

    return next;
}
