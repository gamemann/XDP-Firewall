#pragma once

#include <common/int_types.h>

struct tcp_opts
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
} typedef tcp_opts_t;

struct udp_opts
{
    unsigned int enabled : 1;

    unsigned int do_sport : 1;
    u16 sport;

    unsigned int do_dport : 1;
    u16 dport;
} typedef udp_opts_t;

struct icmp_opts
{
    unsigned int enabled : 1;

    unsigned int do_code : 1;
    u8 code;

    unsigned int do_type : 1;
    u8 type;
} typedef icmp_opts_t;

struct filter
{
    u8 id;

    unsigned int log : 1;

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
    u64 pps;

    unsigned int do_bps : 1;
    u64 bps;

    u64 blocktime;

    tcp_opts_t tcpopts;
    udp_opts_t udpopts;
    icmp_opts_t icmpopts;
} __attribute__((__aligned__(8))) typedef filter_t;

struct stats
{
    u64 allowed;
    u64 dropped;
    u64 passed;
} typedef stats_t;

struct ip_stats
{
    u64 pps;
    u64 bps;
    u64 next_update;
} typedef ip_stats_t ;

struct flow
{
    u32 ip;
    u16 port;
    u8 protocol;
} typedef flow_t;

struct flow6
{
    u128 ip;
    u16 port;
    u8 protocol;
} typedef flow6_t;

struct filter_log_event
{
    u64 ts;
    int filter_id;

    u32 src_ip;
    u32 src_ip6[4];

    u16 src_port;

    u32 dst_ip;
    u32 dst_ip6[4];

    u16 dst_port;

    u8 protocol;

    u64 pps;
    u64 bps;
} typedef filter_log_event_t;