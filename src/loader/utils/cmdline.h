#pragma once

struct cmdline
{
    char *cfgfile;
    unsigned int offload : 1;
    unsigned int skb : 1;
    unsigned int time;
    unsigned int list : 1;
    unsigned int help : 1;
} typedef cmdline_t;

void ParseCommandLine(cmdline_t *cmd, int argc, char *argv[]);