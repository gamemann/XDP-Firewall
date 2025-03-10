#include <rule_del/utils/cli.h>

const struct option opts[] =
{
    { "cfg", required_argument, NULL, 'c' },
    { "help", no_argument, NULL, 'h' },

    { "save", no_argument, NULL, 's' },

    { "mode", required_argument, NULL, 'm' },
    
    { "idx", required_argument, NULL, 'i' },
    { "ip", required_argument, NULL, 'd' },
    { "v6", no_argument, NULL, 'v' },

    { NULL, 0, NULL, 0 }
};

void parse_cli(cli_t* cli, int argc, char* argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:lhm:i:rsv", opts, NULL)) != -1)
    {
        switch (c)
        {
            case 'c':
                cli->cfg_file = optarg;

                break;

            case 'h':
                cli->help = 1;

                break;

            case 's':
                cli->save = 1;

                break;

            case 'm':
                cli->mode = atoi(optarg);

                break;

            case 'i':
                cli->idx = atoi(optarg);

                break;

            case 'd':
                cli->ip = optarg;

                break;

            case 'v':
                cli->v6 = 1;

                break;
            
            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}