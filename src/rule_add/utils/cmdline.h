#pragma once

#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

struct cmdline
{
    const char* cfg_file;

    int help;

    int save;

    int mode;

    int idx;

    const char* ip;
    int v6;

    s64 expires;

    const char* src_ip;
    const char* dst_ip;

    const char* src_ip6;
    const char* dst_ip6;

    s64 pps;
    s64 bps;

    int min_ttl;
    int max_ttl;
    int min_len;
    int max_len;
    int tos;

    int tcp_enabled;
    int tcp_sport;
    int tcp_dport;
    int tcp_urg;
    int tcp_ack;
    int tcp_rst;
    int tcp_psh;
    int tcp_syn;
    int tcp_fin;
    int tcp_ece;
    int tcp_cwr;

    int udp_enabled;
    int udp_sport;
    int udp_dport;

    int icmp_enabled;
    int icmp_code;
    int icmp_type;
} typedef cmdline_t;

void ParseCommandLine(cmdline_t* cmd, int argc, char* argv[]);