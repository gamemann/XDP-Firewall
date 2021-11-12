#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <time.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>

#include <net/if.h>
#include <linux/if_link.h>
#include <arpa/inet.h>

#include <bpf.h>
#include <libbpf.h>

#include "xdpfw.h"
#include "config.h"
#include "cmdline.h"

// Other variables.
static uint8_t cont = 1;
static int filter_map_fd = -1;
static int stats_map_fd = -1;

void signalHndl(int tmp)
{
    cont = 0;
}

void updatefilters(struct config_map *conf)
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

int updateconfig(struct config_map *conf, char *configFile)
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

int findmapfd(struct bpf_object *bpf_obj, const char *mapname)
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

int loadbpfobj(const char *filename)
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

/**
 * Attempts to attach or detach (progfd = -1) a BPF/XDP program to an interface.
 * 
 * @param ifidx The index to the interface to attach to.
 * @param progfd A file description (FD) to the BPF/XDP program.
 * @param cmd A pointer to a cmdline struct that includes command line arguments (mostly checking for offload/HW mode set).
 * 
 * @return Returns the flag (int) it successfully attached the BPF/XDP program with or a negative value for error.
 */
int attachxdp(int ifidx, int progfd, struct cmdline *cmd)
{
    int err;

    char *smode;

    uint32_t flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    uint32_t mode = XDP_FLAGS_DRV_MODE;

    smode = "DRV/native";

    if (cmd->offload)
    {
        smode = "HW/offload";

        mode = XDP_FLAGS_HW_MODE;
    }
    else if (cmd->skb)
    {
        smode = "SKB/generic";
        mode = XDP_FLAGS_SKB_MODE;
    }

    flags |= mode;

    int exit = 0;

    while (!exit)
    {
        // Try loading program with current mode.
        int err;

        err = bpf_set_link_xdp_fd(ifidx, progfd, flags);

        if (err || progfd == -1)
        {
            const char *errmode;

            // Decrease mode.
            switch (mode)
            {
                case XDP_FLAGS_HW_MODE:
                    mode = XDP_FLAGS_DRV_MODE;
                    flags &= ~XDP_FLAGS_HW_MODE;
                    errmode = "HW/offload";

                    break;

                case XDP_FLAGS_DRV_MODE:
                    mode = XDP_FLAGS_SKB_MODE;
                    flags &= ~XDP_FLAGS_DRV_MODE;
                    errmode = "DRV/native";

                    break;

                case XDP_FLAGS_SKB_MODE:
                    // Exit program and set mode to -1 indicating error.
                    exit = 1;
                    mode = -err;
                    errmode = "SKB/generic";

                    break;
            }

            if (progfd != -1)
            {
                fprintf(stderr, "Could not attach with %s mode (%s)(%d).\n", errmode, strerror(-err), err);
            }
            
            if (mode != -err)
            {
                smode = (mode == XDP_FLAGS_HW_MODE) ? "HW/offload" : (mode == XDP_FLAGS_DRV_MODE) ? "DRV/native" : (mode == XDP_FLAGS_SKB_MODE) ? "SKB/generic" : "N/A";
                flags |= mode;
            }
        }
        else
        {
            fprintf(stdout, "Loaded XDP program in %s mode.\n", smode);

            break;
        }
    }

    return mode;
}

int main(int argc, char *argv[])
{
    // Parse the command line.
    struct cmdline cmd = 
    {
        .cfgfile = "/etc/xdpfw/xdpfw.conf",
        .help = 0,
        .list = 0,
        .offload = 0
    };

    parsecommandline(&cmd, argc, argv);

    // Check for help menu.
    if (cmd.help)
    {
        fprintf(stdout, "Usage:\n" \
            "--config -c => Config file location (default is /etc/xdpfw/xdpfw.conf).\n" \
            "--offload -o => Tries to load the XDP program in hardware/offload mode." \
            "--list -l => Print config details including filters (this will exit program after done).\n" \
            "--help -h => Print help menu.\n");

        return EXIT_SUCCESS;
    }

    // Raise RLimit.
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &rl)) 
    {
        fprintf(stderr, "Error setting rlimit.\n");

        return EXIT_FAILURE;
    }

    // Check for --config argument.
    if (cmd.cfgfile == NULL)
    {
        // Assign default.
        cmd.cfgfile = "/etc/xdpfw/xdpfw.conf";
    }

    // Initialize config.
    struct config_map *conf = malloc(sizeof(struct config_map));

    SetConfigDefaults(conf);
    
    // Create last updated variable.
    time_t lastUpdated = time(NULL);
    time_t statsLastUpdated = time(NULL);

    // Update config.
    updateconfig(conf, cmd.cfgfile);

    // Check for list option.
    if (cmd.list)
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
            fprintf(stdout, "Block Time => %" PRIu64 "\n\n", conf->filters[i].blockTime);

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

            fprintf(stdout, "\n\n");
        }

        return EXIT_SUCCESS;
    }

    // Get device.
    int ifidx;

    if ((ifidx = if_nametoindex(conf->interface)) < 0)
    {
        fprintf(stderr, "Error finding device %s.\n", conf->interface);

        return EXIT_FAILURE;
    }

    // XDP variables.
    int progfd;
    char *filename = "/etc/xdpfw/xdpfw_kern.o";

    // Get XDP's ID.
    progfd = loadbpfobj(filename);

    if (progfd <= 0)
    {
        fprintf(stderr, "Error loading eBPF object file. File name => %s.\n", filename);

        return EXIT_FAILURE;
    }
    
    // Attach XDP program.
    int res = attachxdp(ifidx, progfd, &cmd);

    if (res != XDP_FLAGS_HW_MODE && res != XDP_FLAGS_DRV_MODE && res != XDP_FLAGS_SKB_MODE)
    {
        fprintf(stderr, "Error attaching XDP program :: %s (%d)\n", strerror(res), res);

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
    updatefilters(conf);

    // Signal.
    signal(SIGINT, signalHndl);

    // Receive CPU count for stats map parsing.
    int cpus = get_nprocs_conf();

    while (cont)
    {
        // Get current time.
        time_t curTime = time(NULL);

        // Check for auto-update.
        if (conf->updateTime > 0 && (curTime - lastUpdated) > conf->updateTime)
        {
            // Update config.
            updateconfig(conf, cmd.cfgfile);

            // Update BPF maps.
            updatefilters(conf);
            
            // Update last updated variable.
            lastUpdated = time(NULL);
        }

        // Update stats.
        if ((curTime - statsLastUpdated) > 2 && !conf->nostats)
        {
            uint32_t key = 0;
            struct xdpfw_stats stats[cpus];

            uint64_t allowed = 0;
            uint64_t dropped = 0;
            
            bpf_map_lookup_elem(stats_map_fd, &key, &stats);

            for (int i = 0; i < cpus; i++)
            {
                allowed += stats[i].allowed;
                dropped += stats[i].blocked;
            }

            fflush(stdout);
            fprintf(stdout, "\rPackets Allowed: %" PRIu64 " | Packets Blocked: %" PRIu64, allowed, dropped);
        
            statsLastUpdated = time(NULL);
        }

        sleep(1);
    }

    // Detach XDP program.
    attachxdp(ifidx, -1, &cmd);

    // Free config.
    free(conf);

    // Add spacing.
    fprintf(stdout, "\n");

    // Exit program successfully.
    return EXIT_SUCCESS;
}