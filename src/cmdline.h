#pragma once

struct cmdline
{
    char *cfgfile;
    unsigned int offload : 1;
    unsigned int skb : 1;
    unsigned int time;
    unsigned int list : 1;
    unsigned int help : 1;
};

void parsecommandline(struct cmdline *cmd, int argc, char *argv[]);