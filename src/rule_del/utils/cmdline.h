#pragma once

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
} typedef cmdline_t;

void ParseCommandLine(cmdline_t* cmd, int argc, char* argv[]);