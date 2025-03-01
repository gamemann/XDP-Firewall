#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <loader/utils/xdp.h>
#include <loader/utils/config.h>

#include <rule_add/utils/cmdline.h>

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

    // We need to set integers for dynamic filters to -1 since we consider -1 as 'unset'.
    cmd.min_ttl = -1;
    cmd.max_ttl = -1;
    cmd.min_len = -1;
    cmd.max_len = -1;
    cmd.tos = -1;

    cmd.pps = -1;
    cmd.bps = -1;

    cmd.tcp_enabled = -1;
    cmd.tcp_sport = -1;
    cmd.tcp_dport = -1;
    cmd.tcp_urg = -1;
    cmd.tcp_ack = -1;
    cmd.tcp_rst = -1;
    cmd.tcp_psh = -1;
    cmd.tcp_syn = -1;
    cmd.tcp_fin = -1;
    cmd.tcp_ece = -1;
    cmd.tcp_cwr = -1;

    cmd.udp_enabled = -1;
    cmd.udp_sport = -1;
    cmd.udp_dport = -1;
    
    cmd.icmp_enabled = -1;
    cmd.icmp_code = -1;
    cmd.icmp_type = -1;

    ParseCommandLine(&cmd, argc, argv);

    if (!cmd.help)
    {
        printf("Parsed command line...\n");
    }
    else
    {
        printf("Usage: xdpfw-add [OPTIONS]\n\n");

        printf("OPTIONS:\n");
        printf("  -c, --cfg         The path to the config file (default /etc/xdpfw/xdpfw.conf).\n");
        printf("  -s, --save        Saves the new config to file system.\n");
        printf("  -m, --mode        The mode to use (0 = filters, 1 = IPv4 range drop, 2 = IP block map).\n");
        printf("  -i, --idx         The filters index to update when using filters mode (0) (index starts from 1; retrieve index using xdpfw -l).\n");
        printf("  -d, --ip          The IP range or single IP to add (for modes 1 and 2).\n");
        printf("  -v, --v6          If set, parses IP address as IPv6 when adding to block map (for mode 2).\n");
        printf("  -e, --expires     How long to block the IP for in seconds (for mode 2).\n\n");

        printf("Filter Mode Options:\n");
        printf("  --sip             The source IPv4 address (with CIDR support).\n");
        printf("  --dip             The destination IPv4 address (with CIDR support).\n");
        printf("  --sip6            The source IPv6 address.\n");
        printf("  --dip6            The destination IPv6 address.\n");
        printf("  --min-ttl         The minimum IP TTL to match.\n");
        printf("  --max-ttl         The maximum IP TTL to match.\n");
        printf("  --min-len         The minimum packet length to match.\n");
        printf("  --max-len         The maximum packet length to match.\n");
        printf("  --tos             The IP Type of Service to match.\n\n");

        printf("  --pps             The minimum packet rate (per second) to match.\n");
        printf("  --bps             The minimum byte rate (per second) to match\n\n");
        
        printf("  --tcp             Enable or disables matching on the TCP protocol.\n");
        printf("  --tsport          The TCP source port to match on.\n");
        printf("  --tdport          The TCP destination port to match on.\n");
        printf("  --urg             Enables or disables matching on TCP URG flag.\n");
        printf("  --ack             Enables or disables matching on TCP ACK flag.\n");
        printf("  --rst             Enables or disables matching on TCP RST flag.\n");
        printf("  --psh             Enables or disables matching on TCP PSH flag.\n");
        printf("  --syn             Enables or disables matching on TCP SYN flag.\n");
        printf("  --fin             Enables or disables matching on TCP FIN flag.\n");
        printf("  --ece             Enables or disables matching on TCP ECE flag.\n");
        printf("  --cwr             Enables or disables matching on TCP CWR flag.\n\n");

        printf("  --udp             Enable or disables matching on the UDP protocol.\n");
        printf("  --usport          The UDP source port to match on.\n");
        printf("  --udport          The UDP destination port to match on.\n");

        printf("  --icmp            Enable or disables matching on the ICMP protocol.\n");
        printf("  --code            The ICMP code to match on.\n");
        printf("  --type            The ICMP type to match on.\n");

        return EXIT_SUCCESS;
    }

    // Check for config file path.
    if ((cmd.save || cmd.mode == 0) && (!cmd.cfg_file || strlen(cmd.cfg_file) < 1))
    {
        fprintf(stderr, "[ERROR] CFG file not specified or empty. This is required for filters mode or when saving config.\n");

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

        // Create new base filter and set its defaults.
        filter_t new_filter = {0};
        SetFilterDefaults(&new_filter);

        // Determine what index we'll be storing this filter at.
        int idx = -1;

        if (cmd.idx > 0)
        {
            idx = cmd.idx - 1;
        }
        else
        {
            idx = GetNextAvailableFilterIndex(&cfg);
        }

        if (idx < 0)
        {
            fprintf(stderr, "Failed to retrieve filter next. Make sure you haven't exceeded the maximum filters allowed (%d).\n", MAX_FILTERS);

            return EXIT_FAILURE;
        }

        // Fill out new filter.
        if (cmd.src_ip)
        {
            ip_range_t range = ParseIpCidr(cmd.src_ip);

            new_filter.src_ip = range.ip;
            new_filter.src_cidr = range.cidr;
        }

        if (cmd.dst_ip)
        {
            ip_range_t range = ParseIpCidr(cmd.dst_ip);

            new_filter.dst_ip = range.ip;
            new_filter.dst_cidr = range.cidr;
        }

        if (cmd.src_ip6)
        {
            struct in6_addr addr;

            if ((ret = inet_pton(AF_INET6, cmd.src_ip6, &addr)) != 1)
            {
                fprintf(stderr, "Failed to convert source IPv6 address to decimal (%d).\n", ret);

                return EXIT_FAILURE;
            }

            memcpy(new_filter.src_ip6, addr.s6_addr, sizeof(new_filter.src_ip6));
        }

        if (cmd.dst_ip6)
        {
            struct in6_addr addr;

            if ((ret = inet_pton(AF_INET6, cmd.dst_ip6, &addr)) != 1)
            {
                fprintf(stderr, "Failed to convert destination IPv6 address to decimal (%d).\n", ret);

                return EXIT_FAILURE;
            }

            memcpy(new_filter.dst_ip6, addr.s6_addr, sizeof(new_filter.dst_ip6));
        }

        // To Do: See if I can create a macro for below.
        // As long as the naming convention lines up, it should be easily possible.
        if (cmd.pps > -1)
        {
            new_filter.do_pps = 1;
            new_filter.pps = cmd.pps;
        }

        if (cmd.bps > -1)
        {
            new_filter.do_bps = 1;
            new_filter.bps = cmd.bps;
        }

        if (cmd.min_ttl > -1)
        {
            new_filter.do_min_ttl = 1;
            new_filter.min_ttl = cmd.min_ttl;
        }

        if (cmd.max_ttl > -1)
        {
            new_filter.do_max_ttl = 1;
            new_filter.max_ttl = cmd.max_ttl;
        }

        if (cmd.min_len > -1)
        {
            new_filter.do_min_len = 1;
            new_filter.min_len = cmd.min_len;
        }

        if (cmd.max_len > -1)
        {
            new_filter.do_max_len = 1;
            new_filter.max_len = cmd.max_len;
        }

        if (cmd.tos > -1)
        {
            new_filter.do_tos = 1;
            new_filter.tos = cmd.tos;
        }

        if (cmd.tcp_enabled > -1)
        {
            new_filter.tcpopts.enabled = cmd.tcp_enabled;
        }

        if (cmd.tcp_sport > -1)
        {
            new_filter.tcpopts.do_sport = 1;
            new_filter.tcpopts.sport = cmd.tcp_sport;
        }

        if (cmd.tcp_dport > -1)
        {
            new_filter.tcpopts.do_dport = 1;
            new_filter.tcpopts.dport = cmd.tcp_dport;
        }

        if (cmd.tcp_urg > -1)
        {
            new_filter.tcpopts.do_urg = 1;
            new_filter.tcpopts.urg = cmd.tcp_urg;
        }

        if (cmd.tcp_ack > -1)
        {
            new_filter.tcpopts.do_ack = 1;
            new_filter.tcpopts.ack = cmd.tcp_ack;
        }

        if (cmd.tcp_rst > -1)
        {
            new_filter.tcpopts.do_rst = 1;
            new_filter.tcpopts.rst = cmd.tcp_rst;
        }

        if (cmd.tcp_psh > -1)
        {
            new_filter.tcpopts.do_psh = 1;
            new_filter.tcpopts.psh = cmd.tcp_psh;
        }

        if (cmd.tcp_syn > -1)
        {
            new_filter.tcpopts.do_syn = 1;
            new_filter.tcpopts.syn = cmd.tcp_syn;
        }

        if (cmd.tcp_fin > -1)
        {
            new_filter.tcpopts.do_fin = 1;
            new_filter.tcpopts.fin = cmd.tcp_fin;
        }

        if (cmd.tcp_ece > -1)
        {
            new_filter.tcpopts.do_ece = 1;
            new_filter.tcpopts.ece = cmd.tcp_ece;
        }

        if (cmd.tcp_cwr > -1)
        {
            new_filter.tcpopts.do_cwr = 1;
            new_filter.tcpopts.cwr = cmd.tcp_cwr;
        }

        if (cmd.udp_enabled > -1)
        {
            new_filter.udpopts.enabled = cmd.udp_enabled;
        }

        if (cmd.udp_sport > -1)
        {
            new_filter.udpopts.do_sport = 1;
            new_filter.udpopts.sport = cmd.udp_sport;
        }

        if (cmd.udp_dport > -1)
        {
            new_filter.udpopts.do_dport = 1;
            new_filter.udpopts.dport = cmd.udp_dport;
        }

        if (cmd.icmp_enabled > -1)
        {
            new_filter.icmpopts.enabled = cmd.icmp_enabled;
        }

        if (cmd.icmp_code > -1)
        {
            new_filter.icmpopts.do_code = 1;
            new_filter.icmpopts.code = cmd.icmp_code;
        }

        if (cmd.icmp_type > -1)
        {
            new_filter.icmpopts.do_type = 1;
            new_filter.icmpopts.type = cmd.icmp_type;
        }

        // Set filter at index.
        cfg.filters[idx] = new_filter;

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
            fprintf(stderr, "No IP address or range specified. Please set an IP range using -d, --ip arguments.\n");

            return EXIT_FAILURE;
        }

        // Get range map.
        int map_range_drop = GetMapPinFd(XDP_MAP_PIN_DIR, "map_range_drop");

        if (map_range_drop < 0)
        {
            fprintf(stderr, "Failed to retrieve 'map_range_drop' BPF map FD.\n");

            return EXIT_FAILURE;
        }

        printf("Using 'map_range_drop' FD => %d.\n", map_range_drop);

        // Parse IP range.
        ip_range_t range = ParseIpCidr(cmd.ip);

        // Attempt to add range.
        if ((ret = AddRangeDrop(map_range_drop, range.ip, range.cidr)) != 0)
        {
            fprintf(stderr, "Error adding range to BPF map (%d).\n", ret);

            return EXIT_FAILURE;
        }

        printf("Added IP range '%s' to IP range drop map...\n", cmd.ip);

        if (cmd.save)
        {
            // Get next available index.
            int idx = GetNextAvailableIpDropRangeIndex(&cfg);

            if (idx < 0)
            {
                fprintf(stderr, "No available IP drop range indexes. Perhaps the maximum IP ranges has been exceeded?\n");

                return EXIT_FAILURE;
            }

            cfg.drop_ranges[idx] = strdup(cmd.ip);
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

        int expires = 0;

        if (cmd.expires > -1)
        {
            expires = cmd.expires;
        }

        u64 expires_rel = GetBootNanoTime() + ((u64)expires * 1e9);

        int map_block = GetMapPinFd(XDP_MAP_PIN_DIR, "map_block");
        int map_block6 = GetMapPinFd(XDP_MAP_PIN_DIR, "map_block6");

        if (cmd.v6)
        {
            if (map_block6 < 0)
            {
                fprintf(stderr, "Failed to find the 'map_block6' BPF map.\n");

                return EXIT_FAILURE;
            }

            printf("Using 'map_block6' FD => %d.\n", map_block6);

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

            if ((ret = AddBlock6(map_block6, ip, expires_rel)) != 0)
            {
                fprintf(stderr, "Failed to add IP '%s' to BPF map (%d).\n", cmd.ip, ret);

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

            printf("Using 'map_block' FD => %d.\n", map_block);

            struct in_addr addr;

            if ((ret = inet_pton(AF_INET, cmd.ip, &addr)) != 1)
            {
                fprintf(stderr, "Failed to convert IP address '%s' to decimal (%d).\n", cmd.ip, ret);

                return EXIT_FAILURE;
            }

            if ((ret = AddBlock(map_block, addr.s_addr, expires_rel)) != 0)
            {
                fprintf(stderr, "Failed to add IP '%s' too BPF map (%d).\n", cmd.ip, ret);

                return EXIT_FAILURE;
            }

            printf("Added '%s' to block map...\n", cmd.ip);
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