#pragma once

#include <common/int_types.h>
#include <common/types.h>

#include <xdp/utils/helpers.h>

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_FILTERS);
    __type(key, u32);
    __type(value, filter_t);
} filters_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, stats_t);
} stats_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
#ifdef USE_FLOW_RL
    __type(key, flow_t);
#else
    __type(key, u32);
#endif
    __type(value, ip_stats_t);
} ip_stats_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
    __type(key, u32);
    __type(value, u64);
} ip_blacklist_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
#ifdef USE_FLOW_RL
    __type(key, flow6_t);
#else
    __type(key, u128);
#endif
    __type(value, ip_stats_t);
} ip6_stats_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
    __type(key, u128);
    __type(value, u64);
} ip6_blacklist_map SEC(".maps");

#ifdef ENABLE_FILTER_LOGGING
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} filter_log_map SEC(".maps");
#endif