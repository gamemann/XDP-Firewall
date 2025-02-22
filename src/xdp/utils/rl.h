#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

#include <xdp/utils/maps.h>

static __always_inline void UpdateIpStats(u64 *pps, u64 *bps, u32 ip, u16 port, u8 protocol, u16 pkt_len, u64 now);
static __always_inline void UpdateIp6Stats(u64 *pps, u64 *bps, u128 *ip, u16 port, u8 protocol, u16 pkt_len, u64 now);

// NOTE: We include the C source file below because we can't link object files which includes the function logic into the main XDP program because we need to ensure the function is always inlined for performance which doesn't work with linked objects.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "rl.c"