#pragma once

#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <string.h>

struct cli
{
    char* cfg_file;

    int help;

    int save;

    int mode;

    int idx;

    char* ip;
    int v6;

    s64 expires;

    int enabled;
    int log;
    int action;
    s64 block_time;

    char* src_ip;
    char* dst_ip;

    char* src_ip6;
    char* dst_ip6;

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
} typedef cli_t;

void parse_cli(cli_t* cli, int argc, char* argv[]);