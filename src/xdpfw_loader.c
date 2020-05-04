#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <inttypes.h>

#include "../libbpf/src/bpf.h"
#include "../libbpf/src/libbpf.h"

#include "include/xdpfw.h"
#include "include/config.h"

// Command line variables.
static char *configFile;
static int help = 0;

const struct option opts[] =
{
    {"config", required_argument, NULL, 'c'},
    {"help", no_argument, &help, 'h'},
    {NULL, 0, NULL, 0}
};

void parse_command_line(int argc, char *argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:h", opts, 0)) != -1)
    {
        switch (c)
        {
            case 'c':
                configFile = optarg;

                break;

            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;
        }
    }
}

int main(int argc, char *argv[])
{
    // Parse the command line.
    parse_command_line(argc, argv);

    // Check for help menu.
    if (help)
    {
        fprintf(stdout, "Usage:\n" \
            "--config -c => Config file location (default is /etc/xdpfw.conf).\n" \
            "--help -h => Print help menu.\n");

        exit(0);
    }

    // Check for --config argument.
    if (configFile == NULL)
    {
        // Assign default.
        configFile = "/etc/xdpfw.conf";
    }

    // Exit program successfully.
    exit(1);
}
