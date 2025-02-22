#pragma once

#include <common/all.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include <bpf_helpers.h>
#include <xdp/xdp_helpers.h>
#include <xdp/prog_dispatcher.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

static __always_inline u8 IsIpInRange(u32 src_ip, u32 net_ip, u8 cidr);

#include "helpers.c"