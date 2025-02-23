#include <xdp/utils/helpers.h>

/**
 * Checks if an IP is within a specific CIDR range.
 * 
 * @param src_ip The source/main IP to check against.
 * @param net_ip The network IP.
 * @param cidr The CIDR range.
 * 
 * @return 1 on yes, 0 on no.
 */
static __always_inline int IsIpInRange(u32 src_ip, u32 net_ip, u8 cidr)
{
    return !((src_ip ^ net_ip) & htonl(0xFFFFFFFFu << (32 - cidr)));
}