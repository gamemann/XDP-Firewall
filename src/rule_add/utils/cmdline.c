#include <rule_add/utils/cmdline.h>

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

    { "pps", required_argument, NULL, 9 },
    { "bps", required_argument, NULL, 10 },

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

void ParseCommandLine(cmdline_t* cmd, int argc, char* argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:lhm:i:rsv", opts, NULL)) != -1)
    {
        switch (c)
        {
            case 'c':
                cmd->cfg_file = optarg;

                break;

            case 'h':
                cmd->help = 1;

                break;

            case 's':
                cmd->save = 1;

                break;

            case 'm':
                cmd->mode = atoi(optarg);

                break;

            case 'i':
                cmd->idx = atoi(optarg);

                break;

            case 'd':
                cmd->ip = optarg;

                break;

            case 'v':
                cmd->v6 = atoi(optarg);

                break;

            case 'e':
                cmd->expires = strtoll(optarg, NULL, 10);

                break;

            case 28:
                cmd->enabled = atoi(optarg);

                break;

            case 29:
                cmd->action = atoi(optarg);

                break;

            case 30:
                cmd->log = atoi(optarg);

                break;

            case 31:
                cmd->block_time = strtoll(optarg, NULL, 10);

                break;

            case 0:
                cmd->src_ip = optarg;

                break;

            case 1:
                cmd->dst_ip = optarg;

                break;

            case 2:
                cmd->src_ip6 = optarg;
                
                break;

            case 3:
                cmd->dst_ip6 = optarg;

                break;

            case 4:
                cmd->min_ttl = atoi(optarg);

                break;

            case 5:
                cmd->max_ttl = atoi(optarg);

                break;

            case 6:
                cmd->min_len = atoi(optarg);

                break;

            case 7:
                cmd->max_len = atoi(optarg);

                break;

            case 8:
                cmd->tos = atoi(optarg);

                break;

            case 9:
                cmd->pps = strtoll(optarg, NULL, 10);

                break;

            case 10:
                cmd->bps = strtoll(optarg, NULL, 10);

                break;

            case 11:
                cmd->tcp_enabled = atoi(optarg);

                break;

            case 12:
                cmd->tcp_sport = atoi(optarg);

                break;

            case 13:
                cmd->tcp_dport = atoi(optarg);

                break;

            case 14:
                cmd->tcp_urg = atoi(optarg);

                break;

            case 15:
                cmd->tcp_ack = atoi(optarg);

                break;

            case 16:
                cmd->tcp_rst = atoi(optarg);

                break;

            case 17:
                cmd->tcp_psh = atoi(optarg);

                break;

            case 18:
                cmd->tcp_syn = atoi(optarg);

                break;

            case 19:
                cmd->tcp_fin = atoi(optarg);

                break;

            case 20:
                cmd->tcp_ece = atoi(optarg);

                break;

            case 21:
                cmd->tcp_cwr = atoi(optarg);

                break;

            case 22:
                cmd->udp_enabled = atoi(optarg);

                break;

            case 23:
                cmd->udp_sport = atoi(optarg);

                break;

            case 24:
                cmd->udp_dport = atoi(optarg);

                break;

            case 25:
                cmd->icmp_enabled = atoi(optarg);

                break;

            case 26:
                cmd->icmp_code = atoi(optarg);

                break;

            case 27:
                cmd->icmp_type = atoi(optarg);

                break;
            
            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}