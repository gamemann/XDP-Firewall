#include <rule_add/utils/cli.h>

const struct option opts[] =
{
    { "cfg", required_argument, NULL, 'c' },
    { "help", no_argument, NULL, 'h' },

    { "save", no_argument, NULL, 's' },

    { "mode", required_argument, NULL, 'm' },
    
    { "idx", required_argument, NULL, 'i' },

    { "ip", required_argument, NULL, 'd' },
    { "v6", no_argument, NULL, 'v' },
    { "expires", required_argument, NULL, 'e' },

    { "enabled", required_argument, NULL, 28 },
    { "action", required_argument, NULL, 29 },
    { "log", required_argument, NULL, 30 },
    { "block-time", required_argument, NULL, 31 },

    { "sip", required_argument, NULL, 0 },
    { "dip", required_argument, NULL, 1 },
    { "sip6", required_argument, NULL, 2 },
    { "dip6", required_argument, NULL, 3 },
    { "min-ttl", required_argument, NULL, 4 },
    { "max-ttl", required_argument, NULL, 5 },
    { "min-len", required_argument, NULL, 6 },
    { "max-len", required_argument, NULL, 7 },
    { "tos", required_argument, NULL, 8 },

    { "ip-pps", required_argument, NULL, 9 },
    { "ip-bps", required_argument, NULL, 10 },

    { "flow-pps", required_argument, NULL, 32 },
    { "flow-bps", required_argument, NULL, 33 },

    { "tcp", required_argument, NULL, 11 },
    { "tsport", required_argument, NULL, 12 },
    { "tdport", required_argument, NULL, 13 },
    { "urg", required_argument, NULL, 14 },
    { "ack", required_argument, NULL, 15 },
    { "rst", required_argument, NULL, 16 },
    { "psh", required_argument, NULL, 17 },
    { "syn", required_argument, NULL, 18 },
    { "fin", required_argument, NULL, 19 },
    { "ece", required_argument, NULL, 20 },
    { "cwr", required_argument, NULL, 21 },

    { "udp", required_argument, NULL, 22 },
    { "usport", required_argument, NULL, 23 },
    { "udport", required_argument, NULL, 24 },
    
    { "icmp", required_argument, NULL, 25 },
    { "code", required_argument, NULL, 26 },
    { "type", required_argument, NULL, 27 },

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
                cli->v6 = atoi(optarg);

                break;

            case 'e':
                cli->expires = strtoll(optarg, NULL, 10);

                break;

            case 28:
                cli->enabled = atoi(optarg);

                break;

            case 29:
                cli->action = atoi(optarg);

                break;

            case 30:
                cli->log = atoi(optarg);

                break;

            case 31:
                cli->block_time = atoi(optarg);

                break;

            case 0:
                cli->src_ip = optarg;

                break;

            case 1:
                cli->dst_ip = optarg;

                break;

            case 2:
                cli->src_ip6 = optarg;
                
                break;

            case 3:
                cli->dst_ip6 = optarg;

                break;

            case 4:
                cli->min_ttl = atoi(optarg);

                break;

            case 5:
                cli->max_ttl = atoi(optarg);

                break;

            case 6:
                cli->min_len = atoi(optarg);

                break;

            case 7:
                cli->max_len = atoi(optarg);

                break;

            case 8:
                cli->tos = atoi(optarg);

                break;

            case 9:
                cli->ip_pps = strtoll(optarg, NULL, 10);

                break;

            case 10:
                cli->ip_bps = strtoll(optarg, NULL, 10);

                break;

            case 32:
                cli->flow_pps = strtoll(optarg, NULL, 10);

                break;

            case 33:
                cli->flow_bps = strtoll(optarg, NULL, 10);

                break;

            case 11:
                cli->tcp_enabled = atoi(optarg);

                break;

            case 12:
                cli->tcp_sport = optarg;

                break;

            case 13:
                cli->tcp_dport = optarg;

                break;

            case 14:
                cli->tcp_urg = atoi(optarg);

                break;

            case 15:
                cli->tcp_ack = atoi(optarg);

                break;

            case 16:
                cli->tcp_rst = atoi(optarg);

                break;

            case 17:
                cli->tcp_psh = atoi(optarg);

                break;

            case 18:
                cli->tcp_syn = atoi(optarg);

                break;

            case 19:
                cli->tcp_fin = atoi(optarg);

                break;

            case 20:
                cli->tcp_ece = atoi(optarg);

                break;

            case 21:
                cli->tcp_cwr = atoi(optarg);

                break;

            case 22:
                cli->udp_enabled = atoi(optarg);

                break;

            case 23:
                cli->udp_sport = optarg;

                break;

            case 24:
                cli->udp_dport = optarg;

                break;

            case 25:
                cli->icmp_enabled = atoi(optarg);

                break;

            case 26:
                cli->icmp_code = atoi(optarg);

                break;

            case 27:
                cli->icmp_type = atoi(optarg);

                break;
            
            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}