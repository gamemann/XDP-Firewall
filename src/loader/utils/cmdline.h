#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

struct cmdline
{
    char *cfgfile;
    unsigned int offload : 1;
    unsigned int skb : 1;
    unsigned int time;
    unsigned int list : 1;
    unsigned int help : 1;

    int verbose;
    char* log_file;
    char* interface;
    int pin_maps;
    int update_time;
    int no_stats;
    int stats_per_second;
    int stdout_update_time;
} typedef cmdline_t;

void ParseCommandLine(cmdline_t *cmd, int argc, char *argv[]);