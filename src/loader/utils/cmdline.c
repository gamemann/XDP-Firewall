#include <loader/utils/cmdline.h>

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
    { "update-time", required_argument, NULL, 'u' },
    { "no-stats", required_argument, NULL, 'n' },
    { "stats-ps", required_argument, NULL, 1 },
    { "stdout-ut", required_argument, NULL, 2 },

    { NULL, 0, NULL, 0 }
};

/**
 * Parses the command line and stores values in the cmdline structure.
 * 
 * @param cmd A pointer to the cmdline structure.
 * 
 * @return Void
 */
void ParseCommandLine(cmdline_t *cmd, int argc, char *argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:ost:lhv:i:u:n:", opts, NULL)) != -1)
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

            case 'v':
                cmd->verbose = atoi(optarg);

                break;

            case 0:
                cmd->log_file = optarg;

                break;

            case 'i':
                cmd->interface = optarg;

                break;

            case 'u':
                cmd->update_time = atoi(optarg);

                break;

            case 'n':
                cmd->no_stats = atoi(optarg);

                break;

            case 1:
                cmd->stats_per_second = atoi(optarg);

                break;

            case 2:
                cmd->stdout_update_time = atoi(optarg);
                
                break;

            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}