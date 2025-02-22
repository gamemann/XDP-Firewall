#pragma once

#include <common/all.h>

#include <xdp/utils/helpers.h>

#include <xdp/utils/maps.h>

static __always_inline void UpdateIpStats(__u64 *pps, __u64 *bps, u32 ip, u16 port, u8 protocol, u16 pkt_len, __u64 now);
static __always_inline void UpdateIp6Stats(__u64 *pps, __u64 *bps, u128 *ip, u16 port, u8 protocol, u16 pkt_len, __u64 now);

#include "rl.c"