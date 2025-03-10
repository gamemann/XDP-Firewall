#pragma once

#include <common/all.h>

#include <linux/bpf.h>

#include <xdp/xdp_helpers.h>
#include <xdp/prog_dispatcher.h>

enum STATS_TYPE
{
    STATS_TYPE_ALLOWED = 0,
    STATS_TYPE_PASSED,
    STATS_TYPE_DROPPED
} typedef STATS_TYPE_T;

static __always_inline int inc_pkt_stats(stats_t* stats, STATS_TYPE_T type);

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "stats.c"