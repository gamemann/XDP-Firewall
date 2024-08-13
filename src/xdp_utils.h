#pragma once

#include "xdpfw.h"

/**
 * Checks if an IP is within a specific CIDR range.
 * 
 * @param src_ip The source/main IP to check against.
 * @param net_ip The network IP.
 * @param cidr The CIDR range.
 * 
 * @return 1 on yes, 0 on no.
*/
static __always_inline __u8 IsIpInRange(__u32 src_ip, __u32 net_ip, __u8 cidr)
{
    return !((src_ip ^ net_ip) & htonl(0xFFFFFFFFu << (32 - cidr)));
}