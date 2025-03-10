#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

struct cli
{
    const char* cfg_file;

    int help;

    int save;

    int mode;

    int idx;

    const char* ip;
    int v6;
} typedef cli_t;

void parse_cli(cli_t* cli, int argc, char* argv[]);