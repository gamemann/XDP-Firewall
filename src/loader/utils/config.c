#include <loader/utils/config.h>

static FILE *file;

/**
 * Loads the config from the file system.
 * 
 * @param cfg A pointer to the config structure.
 * @param cfg_file The path to the config file.
 * @param overrides Overrides to use instead of config values.
 * 
 * @return 0 on success or 1 on error.
 */
int LoadConfig(config__t *cfg, char *cfg_file, config_overrides_t* overrides)
{
    // Open config file.
    if (OpenCfg(cfg_file) != 0)
    {
        fprintf(stderr, "Error opening config file.\n");
        
        return EXIT_FAILURE;
    }

    SetCfgDefaults(cfg);

    memset(cfg->filters, 0, sizeof(cfg->filters));

    // Read config and check for errors.
    if (ReadCfg(cfg, overrides) != 0)
    {
        fprintf(stderr, "Error reading config file.\n");

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * Sets the config structure's default values.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return Void
 */
void SetCfgDefaults(config__t *cfg)
{
    cfg->verbose = 2;
    cfg->log_file = strdup("/var/log/xdpfw.log");
    cfg->update_time = 0;
    cfg->interface = NULL;
    cfg->no_stats = 0;
    cfg->stats_per_second = 0;
    cfg->stdout_update_time = 1000;

    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_t* filter = &cfg->filters[i];

        filter->set = 0;
        filter->enabled = 1;

        filter->log = 0;

        filter->action = 1;
        filter->src_ip = 0;
        filter->dst_ip = 0;

        memset(filter->src_ip6, 0, 4);
        memset(filter->dst_ip6, 0, 4);

        filter->do_min_len = 0;
        filter->min_len = 0;

        filter->do_max_len = 0;
        filter->max_len = 65535;

        filter->do_min_ttl = 0;
        filter->min_ttl = 0;

        filter->do_max_ttl = 0;
        filter->max_ttl = 255;

        filter->do_tos = 0;
        filter->tos = 0;

        filter->do_pps = 0;
        filter->pps = 0;
        
        filter->do_bps = 0;
        filter->bps = 0;

        filter->block_time = 1;
        
        filter->tcpopts.enabled = 0;
        filter->tcpopts.do_dport = 0;
        filter->tcpopts.do_dport = 0;
        filter->tcpopts.do_urg = 0;
        filter->tcpopts.do_ack = 0;
        filter->tcpopts.do_rst = 0;
        filter->tcpopts.do_psh = 0;
        filter->tcpopts.do_syn = 0;
        filter->tcpopts.do_fin = 0;
        filter->tcpopts.do_ece = 0;
        filter->tcpopts.do_cwr = 0;

        filter->udpopts.enabled = 0;
        filter->udpopts.do_sport = 0;
        filter->udpopts.do_dport = 0;

        filter->icmpopts.enabled = 0;
        filter->icmpopts.do_code = 0;
        filter->icmpopts.do_type = 0;
    }
}

/**
 * Opens the config file.
 * 
 * @param file_name Path to config file.
 * 
 * @return 0 on success or 1 on error.
 */
int OpenCfg(const char *file_name)
{
    // Close any existing files.
    if (file != NULL)
    {
        fclose(file);

        file = NULL;
    }

    file = fopen(file_name, "r");

    if (file == NULL)
    {
        return 1;
    }

    return 0;
}

/**
 * Read the config file and stores values in config structure.
 * 
 * @param cfg A pointer to the config structure.
 * @param overrides Overrides to use instead of config values.
 * 
 * @return 0 on success or 1/-1 on error.
 */
int ReadCfg(config__t *cfg, config_overrides_t* overrides)
{
    // Not sure why this would be set to NULL after checking for it in OpenConfig(), but just for safety.
    if (file == NULL)
    {
        return -1;
    }

    // Initialize config.
    config_t conf;
    config_setting_t *setting;

    config_init(&conf);

    // Attempt to read the config.
    if (config_read(&conf, file) == CONFIG_FALSE)
    {
        LogMsg(cfg, 0, 1, "Error from LibConfig when reading file - %s (Line %d)", config_error_text(&conf), config_error_line(&conf));

        config_destroy(&conf);

        return EXIT_FAILURE;
    }

    int verbose;

    if (config_lookup_int(&conf, "verbose", &verbose) == CONFIG_TRUE || overrides->verbose > -1)
    {
        if (overrides->verbose > -1)
        {
            cfg->verbose = overrides->verbose;
        }
        else
        {
            cfg->verbose = verbose;
        }
    }

    const char* log_file;

    if (config_lookup_string(&conf, "log_file", &log_file) == CONFIG_TRUE || overrides->log_file != NULL)
    {
        // We must free previous value to prevent memory leak.
        if (cfg->log_file != NULL)
        {
            free(cfg->log_file);
            cfg->log_file = NULL;
        }

        if (overrides->log_file != NULL)
        {
            if (strlen(overrides->log_file) > 0)
            {
                cfg->log_file = strdup(overrides->log_file);
                
            }
            else
            {
                cfg->log_file = NULL;
            }
        }
        else
        {
            if (strlen(log_file) > 0)
            {
                cfg->log_file = strdup(log_file);
            }
            else
            {
                cfg->log_file = NULL;
            }
        }
    }

    // Get interface.
    const char *interface;

    if (config_lookup_string(&conf, "interface", &interface) == CONFIG_TRUE || overrides->interface != NULL)
    {
        // We must free previous value to prevent memory leak.
        if (cfg->interface != NULL)
        {
            free(cfg->interface);
            cfg->interface = NULL;
        }

        if (overrides->interface != NULL)
        {
            cfg->interface = strdup(overrides->interface);
        }
        else
        {
            cfg->interface = strdup(interface);
        }
    }

    // Get auto update time.
    int update_time;

    if (config_lookup_int(&conf, "update_time", &update_time) == CONFIG_TRUE || overrides->update_time > -1)
    {
        if (overrides->update_time > -1)
        {
            cfg->update_time = overrides->update_time;
        }
        else
        {
            cfg->update_time = update_time;
        }
    }

    // Get no stats.
    int no_stats;

    if (config_lookup_bool(&conf, "no_stats", &no_stats) == CONFIG_TRUE || overrides->no_stats > -1)
    {
        if (overrides->no_stats > -1)
        {
            cfg->no_stats = overrides->no_stats;
        }
        else
        {
            cfg->no_stats = no_stats;
        }
    }

    // Stats per second.
    int stats_per_second;

    if (config_lookup_bool(&conf, "stats_per_second", &stats_per_second) == CONFIG_TRUE || overrides->stats_per_second > -1)
    {
        if (overrides->stats_per_second > -1)
        {
            cfg->stats_per_second = overrides->stats_per_second;
        }
        else
        {
            cfg->stats_per_second = stats_per_second;
        }
    }

    // Get stdout update time.
    int stdout_update_time;

    if (config_lookup_int(&conf, "stdout_update_time", &stdout_update_time) == CONFIG_TRUE || overrides->stdout_update_time > -1)
    {
        if (overrides->stdout_update_time > -1)
        {
            cfg->stdout_update_time = overrides->stdout_update_time;
        }
        else
        {
            cfg->stdout_update_time = stdout_update_time;
        }
    }

    // Read filters in filters_map structure.
    setting = config_lookup(&conf, "filters");

    // Check if filters map is valid. If not, not a biggie since they aren't required.
    if (setting == NULL)
    {
        LogMsg(cfg, 0, 1, "Error from LibConfig when reading 'filters' array - %s.", config_error_text(&conf));
        
        config_destroy(&conf);

        return 1;
    }

    for (int i = 0; i < config_setting_length(setting); i++)
    {
        filter_t* filter = &cfg->filters[i];

        config_setting_t* filter_cfg = config_setting_get_elem(setting, i);

        if (filter == NULL || filter_cfg == NULL)
        {
            LogMsg(cfg, 0, 1, "[WARNING] Failed to read filter rule at index #%d. 'filter' or 'filter_cfg' is NULL (make sure you didn't exceed the maximum filters allowed!)...");

            continue;
        }

        // Enabled.
        int enabled;

        if (config_setting_lookup_bool(filter_cfg, "enabled",  &enabled) == CONFIG_TRUE)
        {
            filter->enabled = enabled;
        }

        // Log.
        int log;

        if (config_setting_lookup_bool(filter_cfg, "log", &log) == CONFIG_TRUE)
        {
            filter->log = log;
        }

        // Action (required).
        int action;

        if (config_setting_lookup_int(filter_cfg, "action", &action) == CONFIG_TRUE)
        {
            filter->action = action;
        }

        // Source IP (not required).
        const char *sip;

        if (config_setting_lookup_string(filter_cfg, "src_ip", &sip) == CONFIG_TRUE)
        {
            ip_range_t ip = ParseIpCidr(sip);

            filter->src_ip = ip.ip;
            filter->src_cidr = ip.cidr;
        }

        // Destination IP (not required).
        const char *dip;

        if (config_setting_lookup_string(filter_cfg, "dst_ip", &dip) == CONFIG_TRUE)
        {
            ip_range_t ip = ParseIpCidr(dip);

            filter->dst_ip = ip.ip;
            filter->dst_cidr = ip.cidr;
        }

        // Source IP (IPv6) (not required).
        const char *sip6;

        if (config_setting_lookup_string(filter_cfg, "src_ip6", &sip6) == CONFIG_TRUE)
        {
            struct in6_addr in;

            inet_pton(AF_INET6, sip6, &in);

            memcpy(filter->src_ip6, in.__in6_u.__u6_addr32, 4);
        }

        // Destination IP (IPv6) (not required).
        const char *dip6;

        if (config_setting_lookup_string(filter_cfg, "dst_ip6", &dip6) == CONFIG_TRUE)
        {
            struct in6_addr in;

            inet_pton(AF_INET6, dip6, &in);

            memcpy(filter->dst_ip6, in.__in6_u.__u6_addr32, 4);
        }

        // Minimum TTL (not required).
        int min_ttl;

        if (config_setting_lookup_int(filter_cfg, "min_ttl", &min_ttl) == CONFIG_TRUE)
        {
            filter->min_ttl = (u8)min_ttl;
            filter->do_min_ttl = 1;
        }

        // Maximum TTL (not required).
        int max_ttl;

        if (config_setting_lookup_int(filter_cfg, "max_ttl", &max_ttl) == CONFIG_TRUE)
        {
            filter->max_ttl = (u8)max_ttl;
            filter->do_max_ttl = 1;
        }

        // Minimum length (not required).
        int min_len;

        if (config_setting_lookup_int(filter_cfg, "min_len", &min_len) == CONFIG_TRUE)
        {
            filter->min_len = min_len;
            filter->do_min_len = 1;
        }

        // Maximum length (not required).
        int max_len;

        if (config_setting_lookup_int(filter_cfg, "max_len", &max_len) == CONFIG_TRUE)
        {
            filter->max_len = max_len;
            filter->do_max_len = 1;
        }

        // TOS (not required).
        int tos;

        if (config_setting_lookup_int(filter_cfg, "tos", &tos) == CONFIG_TRUE)
        {
            filter->tos = (u8)tos;
            filter->do_tos = 1;
        }

        // PPS (not required).
        long long pps;

        if (config_setting_lookup_int64(filter_cfg, "pps", &pps) == CONFIG_TRUE)
        {
            filter->pps = pps;
            filter->do_pps = 1;
        }

        // BPS (not required).
        long long bps;

        if (config_setting_lookup_int64(filter_cfg, "bps", &bps) == CONFIG_TRUE)
        {
            filter->bps = bps;
            filter->do_bps = 1;
        }

        // Block time (default 1).
        long long block_time;

        if (config_setting_lookup_int64(filter_cfg, "block_time", &block_time) == CONFIG_TRUE)
        {
            filter->block_time = block_time;
        }
        else
        {
            filter->block_time = 1;
        }

        /* TCP options */
        // Enabled.
        int tcpenabled;

        if (config_setting_lookup_bool(filter_cfg, "tcp_enabled", &tcpenabled) == CONFIG_TRUE)
        {
            filter->tcpopts.enabled = tcpenabled;
        }

        // Source port.
        long long tcpsport;

        if (config_setting_lookup_int64(filter_cfg, "tcp_sport", &tcpsport) == CONFIG_TRUE)
        {
            filter->tcpopts.sport = (u16)tcpsport;
            filter->tcpopts.do_sport = 1;
        }

        // Destination port.
        long long tcpdport;

        if (config_setting_lookup_int64(filter_cfg, "tcp_dport", &tcpdport) == CONFIG_TRUE)
        {
            filter->tcpopts.dport = (u16)tcpdport;
            filter->tcpopts.do_dport = 1;
        }

        // URG flag.
        int tcpurg;

        if (config_setting_lookup_bool(filter_cfg, "tcp_urg", &tcpurg) == CONFIG_TRUE)
        {
            filter->tcpopts.urg = tcpurg;
            filter->tcpopts.do_urg = 1;
        }

        // ACK flag.
        int tcpack;

        if (config_setting_lookup_bool(filter_cfg, "tcp_ack", &tcpack) == CONFIG_TRUE)
        {
            filter->tcpopts.ack = tcpack;
            filter->tcpopts.do_ack = 1;
        }
        

        // RST flag.
        int tcprst;

        if (config_setting_lookup_bool(filter_cfg, "tcp_rst", &tcprst) == CONFIG_TRUE)
        {
            filter->tcpopts.rst = tcprst;
            filter->tcpopts.do_rst = 1;
        }

        // PSH flag.
        int tcppsh;

        if (config_setting_lookup_bool(filter_cfg, "tcp_psh", &tcppsh) == CONFIG_TRUE)
        {
            filter->tcpopts.psh = tcppsh;
            filter->tcpopts.do_psh = 1;
        }

        // SYN flag.
        int tcpsyn;

        if (config_setting_lookup_bool(filter_cfg, "tcp_syn", &tcpsyn) == CONFIG_TRUE)
        {
            filter->tcpopts.syn = tcpsyn;
            filter->tcpopts.do_syn = 1;
        }

        // FIN flag.
        int tcpfin;

        if (config_setting_lookup_bool(filter_cfg, "tcp_fin", &tcpfin) == CONFIG_TRUE)
        {
            filter->tcpopts.fin = tcpfin;
            filter->tcpopts.do_fin = 1;
        }

        // ECE flag.
        int tcpece;

        if (config_setting_lookup_bool(filter_cfg, "tcp_ece", &tcpece) == CONFIG_TRUE)
        {
            filter->tcpopts.ece = tcpece;
            filter->tcpopts.do_ece = 1;
        }

        // CWR flag.
        int tcpcwr;

        if (config_setting_lookup_bool(filter_cfg, "tcp_cwr", &tcpcwr) == CONFIG_TRUE)
        {
            filter->tcpopts.cwr = tcpcwr;
            filter->tcpopts.do_cwr = 1;
        }

        /* UDP options */
        // Enabled.
        int udpenabled;

        if (config_setting_lookup_bool(filter_cfg, "udp_enabled", &udpenabled) == CONFIG_TRUE)
        {
            filter->udpopts.enabled = udpenabled;
        }

        // Source port.
        long long udpsport;

        if (config_setting_lookup_int64(filter_cfg, "udp_sport", &udpsport) == CONFIG_TRUE)
        {
            filter->udpopts.sport = (u16)udpsport;
            filter->udpopts.do_sport = 1;
        }

        // Destination port.
        long long udpdport;

        if (config_setting_lookup_int64(filter_cfg, "udp_dport", &udpdport) == CONFIG_TRUE)
        {
            filter->udpopts.dport = (u16)udpdport;
            filter->udpopts.do_dport = 1;
        }

        /* ICMP options */
        // Enabled.
        int icmpenabled;

        if (config_setting_lookup_bool(filter_cfg, "icmp_enabled", &icmpenabled) == CONFIG_TRUE)
        {
            filter->icmpopts.enabled = icmpenabled;
        }

        // ICMP code.
        int icmpcode;

        if (config_setting_lookup_int(filter_cfg, "icmp_code", &icmpcode) == CONFIG_TRUE)
        {
            filter->icmpopts.code = (u8)icmpcode;
            filter->icmpopts.do_code = 1;
        }

        // ICMP type.
        int icmptype;

        if (config_setting_lookup_int(filter_cfg, "icmp_type", &icmptype) == CONFIG_TRUE)
        {
            filter->icmpopts.type = (u8)icmptype;
            filter->icmpopts.do_type = 1;
        }

        // Make sure filter is set.
        filter->set = 1;
    }

    config_destroy(&conf);

    return EXIT_SUCCESS;
}

/**
 * Prints config settings.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return void
 */
void PrintConfig(config__t* cfg)
{
    char* interface = "N/A";

    if (cfg->interface != NULL)
    {
        interface = cfg->interface;
    }

    char* log_file = "N/A";

    if (cfg->log_file != NULL)
    {
        log_file = cfg->log_file;
    }

    printf("Printing config...\n");
    printf("\tGeneral Settings\n");
    
    printf("\t\tVerbose => %d\n", cfg->verbose);
    printf("\t\tLog File => %s\n", log_file);
    printf("\t\tInterface Name => %s\n", interface);
    printf("\t\tUpdate Time => %d\n", cfg->update_time);
    printf("\t\tNo Stats => %d\n", cfg->no_stats);
    printf("\t\tStats Per Second => %d\n", cfg->stats_per_second);
    printf("\t\tStdout Update Time => %d\n\n", cfg->stdout_update_time);

    printf("\tFilters\n");

    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_t *filter = &cfg->filters[i];

        if (!filter->set)
        {
            break;
        }

        printf("\t\tFilter #%d:\n", (i + 1));

        // Main.
        printf("\t\t\tLog => %d\n", filter->log);
        printf("\t\t\tEnabled => %d\n", filter->enabled);
        printf("\t\t\tAction => %d (0 = Block, 1 = Allow).\n\n", filter->action);

        // IP Options.
        printf("\t\t\tIP Options\n");

        // IP addresses require additional code for string printing.
        struct sockaddr_in sin;
        sin.sin_addr.s_addr = filter->src_ip;
        printf("\t\t\t\tSource IPv4 => %s\n", inet_ntoa(sin.sin_addr));
        printf("\t\t\t\tSource CIDR => %d\n", filter->src_cidr);

        struct sockaddr_in din;
        din.sin_addr.s_addr = filter->dst_ip;
        printf("\t\t\t\tDestination IPv4 => %s\n", inet_ntoa(din.sin_addr));
        printf("\t\t\t\tDestination CIDR => %d\n", filter->dst_cidr);

        struct in6_addr sin6;
        memcpy(&sin6, &filter->src_ip6, sizeof(sin6));
        
        char srcipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6, srcipv6, sizeof(srcipv6));

        printf("\t\t\t\tSource IPv6 => %s\n", srcipv6);

        struct in6_addr din6;
        memcpy(&din6, &filter->dst_ip6, sizeof(din6));

        char dstipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &din6, dstipv6, sizeof(dstipv6));

        printf("\t\t\t\tDestination IPv6 => %s\n", dstipv6);

        // Other IP header information.
        printf("\t\t\t\tMax Length => %d\n", filter->max_len);
        printf("\t\t\t\tMin Length => %d\n", filter->min_len);
        printf("\t\t\t\tMax TTL => %d\n", filter->max_ttl);
        printf("\t\t\t\tMin TTL => %d\n", filter->min_ttl);
        printf("\t\t\t\tTOS => %d\n", filter->tos);
        printf("\t\t\t\tPPS => %llu\n", filter->pps);
        printf("\t\t\t\tBPS => %llu\n", filter->bps);
        printf("\t\t\t\tBlock Time => %llu\n\n", filter->block_time);

        // TCP Options.
        printf("\t\t\tTCP Options\n");
        printf("\t\t\t\tTCP Enabled => %d\n", filter->tcpopts.enabled);
        printf("\t\t\t\tTCP Source Port => %d\n", filter->tcpopts.sport);
        printf("\t\t\t\tTCP Destination Port => %d\n", filter->tcpopts.dport);
        printf("\t\t\t\tTCP URG Flag => %d\n", filter->tcpopts.urg);
        printf("\t\t\t\tTCP ACK Flag => %d\n", filter->tcpopts.ack);
        printf("\t\t\t\tTCP RST Flag => %d\n", filter->tcpopts.rst);
        printf("\t\t\t\tTCP PSH Flag => %d\n", filter->tcpopts.psh);
        printf("\t\t\t\tTCP SYN Flag => %d\n", filter->tcpopts.syn);
        printf("\t\t\t\tTCP FIN Flag => %d\n", filter->tcpopts.fin);
        printf("\t\t\t\tTCP ECE Flag => %d\n", filter->tcpopts.ece);
        printf("\t\t\t\tTCP CWR Flag => %d\n\n", filter->tcpopts.cwr);

        // UDP Options.
        printf("\t\t\tUDP Options\n");
        printf("\t\t\t\tUDP Enabled => %d\n", filter->udpopts.enabled);
        printf("\t\t\t\tUDP Source Port => %d\n", filter->udpopts.sport);
        printf("\t\t\t\tUDP Destination Port => %d\n\n", filter->udpopts.dport);

        // ICMP Options.
        printf("\t\t\tICMP Options\n");
        printf("\t\t\t\tICMP Enabled => %d\n", filter->icmpopts.enabled);
        printf("\t\t\t\tICMP Code => %d\n", filter->icmpopts.code);
        printf("\t\t\t\tICMP Type => %d\n", filter->icmpopts.type);

        printf("\n\n");
    }
}