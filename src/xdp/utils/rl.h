#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

#include <xdp/utils/maps.h>

#ifdef ENABLE_FILTERS
static __always_inline int update_ip_stats(u64 *pps, u64 *bps, u32 ip, u16 pkt_len, u64 now);
static __always_inline int update_ip6_stats(u64 *pps, u64 *bps, u128 *ip, u16 pkt_len, u64 now);
static __always_inline int update_flow_stats(u64 *pps, u64 *bps, u32 ip, u16 port, u8 protocol, u16 pkt_len, u64 now);
static __always_inline int update_flow6_stats(u64 *pps, u64 *bps, u128 *ip, u16 port, u8 protocol, u16 pkt_len, u64 now);
#endif

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "rl.c"