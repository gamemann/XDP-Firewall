#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>

#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#include "../libbpf/src/bpf.h"
#include "../libbpf/src/libbpf.h"

#include "include/xdpfw.h"
#include "include/config.h"

// Command line variables.
static char *configFile;
static int help = 0;
static int list = 0;

const struct option opts[] =
{
    {"config", required_argument, NULL, 'c'},
    {"list", no_argument, &list, 'l'},
    {"help", no_argument, &help, 'h'},
    {NULL, 0, NULL, 0}
};

// Other variables.
static uint8_t cont = 1;
static int filter_map_fd = -1;
static int stats_map_fd = -1;

void signalHndl(int tmp)
{
    cont = 0;
}

void parse_command_line(int argc, char *argv[])
{
    int c;

    while ((c = getopt_long(argc, argv, "c:lh", opts, NULL)) != -1)
    {
        switch (c)
        {
            case 'c':
                configFile = optarg;

                break;

            case 'l':
                list = 1;

                break;

            case 'h':
                help = 1;

                break;

            case '?':
                fprintf(stderr, "Missing argument option...\n");

                break;

            default:
                break;
        }
    }
}

void update_BPF(struct config_map *conf)
{
    // Loop through all filters and delete the map.
    for (uint8_t i = 0; i < MAX_FILTERS; i++)
    {
        uint32_t key = i;

        bpf_map_delete_elem(filter_map_fd, &key);
    }

    // Add a filter to the filter maps.
    for (uint32_t i = 0; i < MAX_FILTERS; i++)
    {
        // Check if we have a valid ID.
        if (conf->filters[i].id < 1)
        {
            break;
        }

        // Attempt to update BPF map.
        if (bpf_map_update_elem(filter_map_fd, &i, &conf->filters[i], BPF_ANY) == -1)
        {
            fprintf(stderr, "Error updating BPF item #%d\n", i);
        }
    }
}

int update_config(struct config_map *conf, char *configFile)
{
    // Open config file.
    if (OpenConfig(configFile) != 0)
    {
        fprintf(stderr, "Error opening filters file: %s\n", configFile);
        
        return -1;
    }

    SetConfigDefaults(conf);

    for (uint16_t i = 0; i < MAX_FILTERS; i++)
    {
        conf->filters[i] = (struct filter) {0};
    }

    // Read config and check for errors.
    if (ReadConfig(conf) != 0)
    {
        fprintf(stderr, "Error reading filters file.\n");

        return -1;
    }

    return 0;
}

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_map *map;
    int fd = -1;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", mapname);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}


int load_bpf_object_file__simple(const char *filename)
{
    int first_prog_fd = -1;
    struct bpf_object *obj;
    int err;

    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);

    if (err)
    {
        fprintf(stderr, "Error loading XDP program. File => %s. Error => %s. Error Num => %d\n", filename, strerror(-err), err);

        return -1;
    }

    filter_map_fd = find_map_fd(obj, "filters_map");
    stats_map_fd = find_map_fd(obj, "stats_map");

    return first_prog_fd;
}

static int xdp_detach(int ifindex, uint32_t xdp_flags)
{
    int err;

    err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

    if (err < 0)
    {
        fprintf(stderr, "Error detaching XDP program. Error => %s. Error Num => %.d\n", strerror(-err), err);

        return -1;
    }

    return EXIT_SUCCESS;
}

static int xdp_attach(int ifindex, uint32_t *xdp_flags, int prog_fd)
{
    int err;
    
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, *xdp_flags);

    if (err == -EEXIST && !(*xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
    {
        
        uint32_t oldflags = *xdp_flags;

        *xdp_flags &= ~XDP_FLAGS_MODES;
        *xdp_flags |= (oldflags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;

        err = bpf_set_link_xdp_fd(ifindex, -1, *xdp_flags);

        if (!err)
        {
            err = bpf_set_link_xdp_fd(ifindex, prog_fd, oldflags);
        }
    }

    // Check for no XDP-Native support.
    if (err)
    {
        fprintf(stdout, "XDP-Native may not be supported with this NIC. Using SKB instead.\n");

        // Remove DRV Mode flag.
        if (*xdp_flags & XDP_FLAGS_DRV_MODE)
        {
            *xdp_flags &= ~XDP_FLAGS_DRV_MODE;
        }

        // Add SKB Mode flag.
        if (!(*xdp_flags & XDP_FLAGS_SKB_MODE))
        {
            *xdp_flags |= XDP_FLAGS_SKB_MODE;
        }

        err = bpf_set_link_xdp_fd(ifindex, prog_fd, *xdp_flags);
    }

    if (err < 0)
    {
        fprintf(stderr, "Error attaching XDP program. Error => %s. Error Num => %d. IfIndex => %d.\n", strerror(-err), -err, ifindex);

        switch(-err)
        {
            case EBUSY:

            case EEXIST:
            {
                xdp_detach(ifindex, *xdp_flags);
                fprintf(stderr, "Additional: XDP already loaded on device.\n");
                break;
            }

            case EOPNOTSUPP:
                fprintf(stderr, "Additional: XDP-native nor SKB not supported? Not sure how that's possible.\n");

                break;

            default:
                break;
        }

        return -1;
    }

    return EXIT_SUCCESS;
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
            "--list -l => Print config details including filters (this will exit program after done).\n" \
            "--help -h => Print help menu.\n");

        return EXIT_SUCCESS;
    }

    // Check for --config argument.
    if (configFile == NULL)
    {
        // Assign default.
        configFile = "/etc/xdpfw/xdpfw.conf";
    }

    // Initialize config.
    struct config_map *conf = malloc(sizeof(struct config_map));
    
    SetConfigDefaults(conf);
    
    // Create last updated variable.
    time_t lastUpdated = time(NULL);
    time_t statsLastUpdated = time(NULL);

    // Update config.
    update_config(conf, configFile);

    // Check for list option.
    if (list)
    {
        fprintf(stdout, "Details:\n");
        fprintf(stdout, "Interface Name => %s\n", conf->interface);
        fprintf(stdout, "Update Time => %" PRIu16 "\n", conf->updateTime);

        for (uint16_t i = 0; i < MAX_FILTERS; i++)
        {
            if (conf->filters[i].id < 1)
            {
                break;
            }

            fprintf(stdout, "Filter #%" PRIu16 ":\n", (i + 1));

            // Main.
            fprintf(stdout, "ID => %d\n", conf->filters[i].id);
            fprintf(stdout, "Enabled => %" PRIu8 "\n", conf->filters[i].enabled);
            fprintf(stdout, "Action => %" PRIu8 " (0 = Block, 1 = Allow).\n", conf->filters[i].action);

            // IP addresses.
            struct sockaddr_in sin;
            sin.sin_addr.s_addr = conf->filters[i].srcIP;
            fprintf(stdout, "Source IP => %s\n", inet_ntoa(sin.sin_addr));

            struct sockaddr_in din;
            din.sin_addr.s_addr = conf->filters[i].dstIP;
            fprintf(stdout, "Destination IP => %s\n", inet_ntoa(din.sin_addr));

            // Other IP header information.
            fprintf(stdout, "Max Length => %" PRIu16 "\n", conf->filters[i].max_len);
            fprintf(stdout, "Min Length => %" PRIu16 "\n", conf->filters[i].min_len);
            fprintf(stdout, "Max TTL => %" PRIu8 "\n", conf->filters[i].max_ttl);
            fprintf(stdout, "Min TTL => %" PRIu8 "\n", conf->filters[i].min_ttl);
            fprintf(stdout, "TOS => %" PRIu8 "\n", conf->filters[i].tos);
            fprintf(stdout, "PPS => %" PRIu64 "\n", conf->filters[i].pps);
            fprintf(stdout, "BPS => %" PRIu64 "\n\n", conf->filters[i].bps);

            // TCP Options.
            fprintf(stdout, "TCP Enabled => %" PRIu8 "\n", conf->filters[i].tcpopts.enabled);
            fprintf(stdout, "TCP Source Port => %" PRIu16 "\n", conf->filters[i].tcpopts.sport);
            fprintf(stdout, "TCP Destination Port => %" PRIu16 "\n", conf->filters[i].tcpopts.dport);
            fprintf(stdout, "TCP URG Flag => %" PRIu8 "\n", conf->filters[i].tcpopts.urg);
            fprintf(stdout, "TCP ACK Flag => %" PRIu8 "\n", conf->filters[i].tcpopts.ack);
            fprintf(stdout, "TCP RST Flag => %" PRIu8 "\n", conf->filters[i].tcpopts.rst);
            fprintf(stdout, "TCP PSH Flag => %" PRIu8 "\n", conf->filters[i].tcpopts.psh);
            fprintf(stdout, "TCP SYN Flag => %" PRIu8 "\n", conf->filters[i].tcpopts.syn);
            fprintf(stdout, "TCP FIN Flag => %" PRIu8 "\n\n", conf->filters[i].tcpopts.fin);

            // UDP Options.
            fprintf(stdout, "UDP Enabled => %" PRIu8 "\n", conf->filters[i].udpopts.enabled);
            fprintf(stdout, "UDP Source Port => %" PRIu16 "\n", conf->filters[i].udpopts.sport);
            fprintf(stdout, "UDP Destination Port => %" PRIu16 "\n\n", conf->filters[i].udpopts.dport);

            // ICMP Options.
            fprintf(stdout, "ICMP Enabled => %" PRIu8 "\n", conf->filters[i].icmpopts.enabled);
            fprintf(stdout, "ICMP Code => %" PRIu8 "\n", conf->filters[i].icmpopts.code);
            fprintf(stdout, "ICMP Type => %" PRIu8 "\n", conf->filters[i].icmpopts.type);

            // Payload.
            if (conf->filters[i].payloadLen > 0)
            {
                fprintf(stdout, "\nPayload (%d) => ", conf->filters[i].payloadLen);

                for(uint16_t j = 0; j < conf->filters[i].payloadLen; j++)
                {
                    fprintf(stdout, "%2hhx ", conf->filters[i].payloadMatch[j]);
                }

                fprintf(stdout, "\n");
            }

            fprintf(stdout, "\n\n");
        }

        return EXIT_SUCCESS;
    }

    // Get device.
    int dev;

    if ((dev = if_nametoindex(conf->interface)) < 0)
    {
        fprintf(stderr, "Error finding device %s.\n", conf->interface);

        return EXIT_FAILURE;
    }

    // XDP variables.
    int prog_fd;
    uint32_t xdpflags;
    char *filename = "/etc/xdpfw/xdpfw_kern.o";

    xdpflags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

    // Get XDP's ID.
    prog_fd = load_bpf_object_file__simple(filename);

    if (prog_fd <= 0)
    {
        fprintf(stderr, "Error loading eBPF object file. File name => %s.\n", filename);

        return EXIT_FAILURE;
    }
    
    // Attach XDP program to device.
    if (xdp_attach(dev, &xdpflags, prog_fd) != 0)
    {
        return EXIT_FAILURE;
    }

    // Check for valid maps.
    if (filter_map_fd < 0)
    {
        fprintf(stderr, "Error finding 'filters_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    if (stats_map_fd < 0)
    {
        fprintf(stderr, "Error finding 'stats_map' BPF map.\n");

        return EXIT_FAILURE;
    }

    // Update BPF maps.
    update_BPF(conf);

    // Signal.
    signal(SIGINT, signalHndl);

    while (cont)
    {
        // Get current time.
        time_t curTime = time(NULL);

        // Check for auto-update.
        if (conf->updateTime > 0 && (curTime - lastUpdated) > conf->updateTime)
        {
            // Update config.
            update_config(conf, configFile);

            // Update BPF maps.
            update_BPF(conf);
            
            // Update last updated variable.
            lastUpdated = time(NULL);
        }

        // Update stats.
        if ((curTime - statsLastUpdated) > 2 && !conf->nostats)
        {
            uint32_t key = 0;
            struct xdpfw_stats stats;
            
            bpf_map_lookup_elem(stats_map_fd, &key, &stats);

            fflush(stdout);
            fprintf(stdout, "\rPackets Allowed: %" PRIu64 " | Packets Blocked: %" PRIu64, stats.allowed, stats.blocked);
        
            statsLastUpdated = time(NULL);
        }

        sleep(1);
    }

    // Detach XDP program.
    if (xdp_detach(dev, xdpflags) != 0)
    {
        fprintf(stderr, "Error removing XDP program from device %s\n", conf->interface);

        return EXIT_FAILURE;
    }

    // Free config.
    free(conf);

    // Add spacing.
    fprintf(stdout, "\n");

    // Exit program successfully.
    return EXIT_SUCCESS;
}