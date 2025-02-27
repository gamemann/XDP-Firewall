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
} map_filters SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, stats_t);
} map_stats SEC(".maps");

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
} map_ip_stats SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
    __type(key, u32);
    __type(value, u64);
} map_ip_blacklist SEC(".maps");

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
} map_ip6_stats SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
    __type(key, u128);
    __type(value, u64);
} map_ip6_blacklist SEC(".maps");

#ifdef ENABLE_FILTER_LOGGING
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} map_filter_log SEC(".maps");
#endif