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
    int block_time;

    char* src_ip;
    char* dst_ip;

    char* src_ip6;
    char* dst_ip6;

    s64 ip_pps;
    s64 ip_bps;

    s64 flow_pps;
    s64 flow_bps;

    int min_ttl;
    int max_ttl;
    int min_len;
    int max_len;
    int tos;

    int tcp_enabled;
    char* tcp_sport;
    char* tcp_dport;
    int tcp_urg;
    int tcp_ack;
    int tcp_rst;
    int tcp_psh;
    int tcp_syn;
    int tcp_fin;
    int tcp_ece;
    int tcp_cwr;

    int udp_enabled;
    char* udp_sport;
    char* udp_dport;

    int icmp_enabled;
    int icmp_code;
    int icmp_type;
} typedef cli_t;

void parse_cli(cli_t* cli, int argc, char* argv[]);