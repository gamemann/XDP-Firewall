#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <loader/utils/xdp.h>
#include <loader/utils/config.h>

#include <rule_del/utils/cmdline.h>

// These are required due to being extern with Loader.
// To Do: Figure out a way to not require the below without requiring separate object files.
int cont = 0;
int doing_stats = 0;

int main(int argc, char *argv[])
{
    int ret;

    // Parse command line.
    cmdline_t cmd = {0};
    cmd.cfg_file = CONFIG_DEFAULT_PATH;

    ParseCommandLine(&cmd, argc, argv);

    if (!cmd.help)
    {
        printf("Parsed command line...\n");
    } else
    {
        printf("Usage: xdpfw-del [OPTIONS]\n\n");
        printf("OPTIONS:\n");
        printf("  -c, --cfg         The path to the config file (default /etc/xdpfw/xdpfw.conf).\n");
        printf("  -s, --save        Saves the new config to file system.\n");
        printf("  -m, --mode        The mode to use (0 = filters, 1 = IPv4 range drop, 2 = IP block map).\n");
        printf("  -i, --idx         The filters index to remove when using filters mode (0) (index starts from 1; retrieve index using xdpfw -l).\n");
        printf("  -d, --ip          The IP range or single IP to use (for modes 1 and 2).\n");
        printf("  -v, --v6          If set, parses IP address as IPv6 when removing from block map (for mode 2).\n");

        return EXIT_SUCCESS;
    }

    // Check for config file path.
    if ((cmd.save || cmd.mode == 0) && (!cmd.cfg_file || strlen(cmd.cfg_file) < 1))
    {
        fprintf(stderr, "[ERROR] CFG file not specified or empty. This is required for current mode or options set.\n");

        return EXIT_FAILURE;
    }

    // Load config.
    config__t cfg = {0};
    
    if (cmd.save || cmd.mode == 0)
    {
        if ((ret = LoadConfig(&cfg, cmd.cfg_file, NULL)) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to load config at '%s' (%d)\n", cmd.cfg_file, ret);

            return EXIT_FAILURE;
        }

        printf("Loaded config...\n");
    }

    // Handle filters mode.
    if (cmd.mode == 0)
    {
        printf("Using filters mode (0)...\n");

        // Check index.
        if (cmd.idx < 1)
        {
            fprintf(stderr, "Invalid filter index. Index must start from 1.\n");

            return EXIT_FAILURE;
        }

        // Retrieve filters map FD.
        int map_filters = GetMapPinFd(XDP_MAP_PIN_DIR, "map_filters");

        if (map_filters < 0)
        {
            fprintf(stderr, "[ERROR] Failed to retrieve BPF map 'map_filters' from file system.\n");

            return EXIT_FAILURE;
        }

        printf("Using 'map_filters' FD => %d...\n", map_filters);

        int index = -1;
        int cfg_idx = cmd.idx - 1;
        int cur_idx = 0;

        // This is where things are a bit tricky due to the layout of our filtering system in XDP.
        // Since each filter rule doesn't have any unique identifier other than the index, we need to use that.
        // However, rules that are not enabled are not inserted into the BPF map which can mismatch the indexes in the config and XDP program.
        // So we need to loop through each and ignore disabled rules.
        for (int i = 0; i < MAX_FILTERS; i++)
        {
            filter_t* filter = &cfg.filters[i];

            if (!filter->set || !filter->enabled)
            {
                continue;
            }

            if (i == cur_idx)
            {
                index = cur_idx;

                break;
            }

            cur_idx++;
        }

        if (index < 0)
        {
            fprintf(stderr, "[ERROR] Failed to find proper index in config file (%d).\n", index);

            return EXIT_FAILURE;
        }

        // Unset affected filter in config.
        if (cmd.save)
        {
            cfg.filters[cfg_idx].set = 0;
        }

        // Update filters.
        fprintf(stdout, "Updating filters...\n");

        UpdateFilters(map_filters, &cfg);
    }
    // Handle IPv4 range drop mode.
    else if (cmd.mode == 1)
    {
        printf("Using IPv4 range drop mode (1)...\n");

        // Make sure IP range is specified.
        if (!cmd.ip)
        {
            fprintf(stderr, "No IP address or range specified. Please set an IP range using -s, --ip arguments.\n");

            return EXIT_FAILURE;
        }

        // Get range map.
        int map_range_drop = GetMapPinFd(XDP_MAP_PIN_DIR, "map_range_drop");

        if (map_range_drop < 0)
        {
            fprintf(stderr, "Failed to retrieve 'map_range_drop' BPF map FD.\n");

            return EXIT_FAILURE;
        }

        // Parse IP range.
        ip_range_t range = ParseIpCidr(cmd.ip);

        // Attempt to delete range.
        if ((ret = DeleteRangeDrop(map_range_drop, range.ip, range.cidr)) != 0)
        {
            fprintf(stderr, "Error deleting range from BPF map (%d).\n", ret);

            return EXIT_FAILURE;
        }

        printf("Removed IP range '%s' from BPF map.\n", cmd.ip);

        if (cmd.save)
        {
            // Loop through IP drop ranges and unset if found.
            for (int i = 0; i < MAX_IP_RANGES; i++)
            {
                const char* cur_range = cfg.drop_ranges[i];

                if (!cur_range)
                {
                    continue;
                }

                if (strcmp(cur_range, cmd.ip) != 0)
                {
                    continue;
                }

                free((void*)cfg.drop_ranges[i]);
                cfg.drop_ranges[i] = NULL;
            }
        }
    }
    // Handle block map mode.
    else
    {
        printf("Using source IP block mode (2)...\n");

        if (!cmd.ip)
        {
            fprintf(stderr, "No source IP address specified. Please set an IP using -s, --ip arguments.\n");

            return EXIT_FAILURE;
        }

        int map_block = GetMapPinFd(XDP_MAP_PIN_DIR, "map_block");
        int map_block6 = GetMapPinFd(XDP_MAP_PIN_DIR, "map_block6");

        if (cmd.v6)
        {
            if (map_block6 < 0)
            {
                fprintf(stderr, "Failed to find the 'map_block6' BPF map.\n");

                return EXIT_FAILURE;
            }

            struct in6_addr addr;

            if ((ret = inet_pton(AF_INET6, cmd.ip, &addr)) != 1)
            {
                fprintf(stderr, "Failed to convert IPv6 address '%s' to decimal (%d).\n", cmd.ip, ret);

                return EXIT_FAILURE;
            }

            u128 ip = 0;

            for (int i = 0; i < 16; i++)
            {
                ip = (ip << 8) | addr.s6_addr[i];
            }

            if ((ret = DeleteBlock6(map_block6, ip)) != 0)
            {
                fprintf(stderr, "Failed to delete IP '%s' from BPF map (%d).\n", cmd.ip, ret);

                return EXIT_FAILURE;
            }
        }
        else
        {
            if (map_block < 0)
            {
                fprintf(stderr, "Failed to find the 'map_block' BPF map.\n");

                return EXIT_FAILURE;
            }

            struct in_addr addr;

            if ((ret = inet_pton(AF_INET, cmd.ip, &addr)) != 1)
            {
                fprintf(stderr, "Failed to convert IP address '%s' to decimal (%d).\n", cmd.ip, ret);

                return EXIT_FAILURE;
            }

            if ((ret = DeleteBlock(map_block, addr.s_addr)) != 0)
            {
                fprintf(stderr, "Failed to delete IP '%s' from BPF map (%d).\n", cmd.ip, ret);

                return EXIT_FAILURE;
            }

            printf("Deleted '%s' from block map...\n", cmd.ip);
        }
    }

    if (cmd.save)
    {
        // Save config.
        printf("Saving config...\n");

        if ((ret = SaveCfg(&cfg, cmd.cfg_file)) != 0)
        {
            fprintf(stderr, "[ERROR] Failed to save config.\n");

            return EXIT_FAILURE;
        }
    }

    printf("Success! Exiting.\n");

    return EXIT_SUCCESS;
}