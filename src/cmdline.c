#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "cmdline.h"

const struct option opts[] =
{
    {"config", required_argument, NULL, 'c'},
    {"offload", no_argument, NULL, 'o'},
    {"skb", no_argument, NULL, 's'},
    {"time", required_argument, NULL, 't'},
    {"list", no_argument, NULL, 'l'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

/**
 * Parses the command line and stores values in the cmdline structure.
 * 
 * @param cmd A pointer to the cmdline structure.
 * 
 * @return Void
*/
void parsecommandline(struct cmdline *cmd, int argc, char *argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:ost:lh", opts, NULL)) != -1)
    {
        switch (c)
        {
            case 'c':
                cmd->cfgfile = optarg;

                break;

            case 'o':
                cmd->offload = 1;

                break;

            case 's':
                cmd->skb = 1;

                break;

            case 't':
                cmd->time = atoi(optarg);

                break;

            case 'l':
                cmd->list = 1;

                break;

            case 'h':
                cmd->help = 1;

                break;

            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}