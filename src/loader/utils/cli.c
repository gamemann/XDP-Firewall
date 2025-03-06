#include <loader/utils/cli.h>

const struct option opts[] =
{
    { "config", required_argument, NULL, 'c' },
    { "offload", no_argument, NULL, 'o' },
    { "skb", no_argument, NULL, 's' },
    { "time", required_argument, NULL, 't' },
    { "list", no_argument, NULL, 'l' },
    { "help", no_argument, NULL, 'h' },

    { "verbose", required_argument, NULL, 'v' },
    { "log-file", required_argument, NULL, 0 },
    { "interface", required_argument, NULL, 'i' },
    { "pin-maps", required_argument, NULL, 'p' },
    { "update-time", required_argument, NULL, 'u' },
    { "no-stats", required_argument, NULL, 'n' },
    { "stats-ps", required_argument, NULL, 1 },
    { "stdout-ut", required_argument, NULL, 2 },

    { NULL, 0, NULL, 0 }
};

/**
 * Parses the command line and stores values in the cli structure.
 * 
 * @param cli A pointer to the cli structure.
 * 
 * @return Void
 */
void parse_cli(cli_t *cli, int argc, char *argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:ost:lhv:i:p:u:n:", opts, NULL)) != -1)
    {
        switch (c)
        {
            case 'c':
                cli->cfg_file = optarg;

                break;

            case 'o':
                cli->offload = 1;

                break;

            case 's':
                cli->skb = 1;

                break;

            case 't':
                cli->time = atoi(optarg);

                break;

            case 'l':
                cli->list = 1;

                break;

            case 'h':
                cli->help = 1;

                break;

            case 'v':
                cli->verbose = atoi(optarg);

                break;

            case 0:
                cli->log_file = optarg;

                break;

            case 'i':
                cli->interface = optarg;

                break;

            case 'p':
                cli->pin_maps = atoi(optarg);

                break;

            case 'u':
                cli->update_time = atoi(optarg);

                break;

            case 'n':
                cli->no_stats = atoi(optarg);

                break;

            case 1:
                cli->stats_per_second = atoi(optarg);

                break;

            case 2:
                cli->stdout_update_time = atoi(optarg);
                
                break;

            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}