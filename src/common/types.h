#pragma once

#include <common/int_types.h>

struct tcpopts
{
    unsigned int enabled : 1;

    unsigned int do_sport : 1;
    u16 sport;

    unsigned int do_dport : 1;
    u16 dport;

    // TCP flags.
    unsigned int do_urg : 1;
    unsigned int urg : 1;

    unsigned int do_ack : 1;
    unsigned int ack : 1;

    unsigned int do_rst : 1;
    unsigned int rst : 1;

    unsigned int do_psh : 1;
    unsigned int psh : 1;

    unsigned int do_syn : 1;
    unsigned int syn : 1;

    unsigned int do_fin : 1;
    unsigned int fin : 1;

    unsigned int do_ece : 1;
    unsigned int ece : 1;

    unsigned int do_cwr : 1;
    unsigned int cwr : 1;
};

struct udpopts
{
    unsigned int enabled : 1;

    unsigned int do_sport : 1;
    u16 sport;

    unsigned int do_dport : 1;
    u16 dport;
};

struct icmpopts
{
    unsigned int enabled : 1;

    unsigned int do_code : 1;
    u8 code;

    unsigned int do_type : 1;
    u8 type;
};

struct filter
{
    u8 id;

    unsigned int enabled : 1;

    u8 action;

    u32 src_ip;
    u8 src_cidr;

    u32 dst_ip;
    u8 dst_cidr;

    u32 src_ip6[4];
    u32 dst_ip6[4];

    unsigned int do_min_ttl : 1;
    u8 min_ttl;

    unsigned int do_max_ttl : 1;
    u8 max_ttl;

    unsigned int do_min_len : 1;
    u16 min_len;

    unsigned int do_max_len : 1;
    u16 max_len;

    unsigned int do_tos : 1;
    u8 tos;

    unsigned int do_pps : 1;
    __u64 pps;

    unsigned int do_bps : 1;
    __u64 bps;

    __u64 blocktime;

    struct tcpopts tcpopts;
    struct udpopts udpopts;
    struct icmpopts icmpopts;
} __attribute__((__aligned__(8)));

struct stats
{
    __u64 allowed;
    __u64 dropped;
    __u64 passed;
};

struct ip_stats
{
    __u64 pps;
    __u64 bps;
    __u64 next_update;
};

struct flow
{
    u32 ip;
    u16 port;
    u8 protocol;
};

struct flow6
{
    u128 ip;
    u16 port;
    u8 protocol;
};