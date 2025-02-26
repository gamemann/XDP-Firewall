#include <loader/utils/config.h>

#include <loader/utils/helpers.h>

static FILE *file;

/**
 * Loads the config from the file system.
 * 
 * @param cfg A pointer to the config structure.
 * @param cfg_file The path to the config file.
 * 
 * @return 0 on success or 1 on error.
 */
int LoadConfig(config__t *cfg, char *cfg_file)
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
    if (ReadCfg(cfg) != 0)
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
    cfg->verbose = 1;
    cfg->log_file = strdup("/var/log/xdpfw/xdpfw.log");
    cfg->updatetime = 0;
    cfg->interface = NULL;
    cfg->nostats = 0;
    cfg->stdout_update_time = 1000;

    for (int i = 0; i < MAX_FILTERS; i++)
    {
        cfg->filters[i].id = 0;
        cfg->filters[i].enabled = 0;
        cfg->filters[i].action = 0;
        cfg->filters[i].src_ip = 0;
        cfg->filters[i].dst_ip = 0;

        for (int j = 0; j < 4; j++)
        {
            cfg->filters[i].src_ip6[j] = 0;
            cfg->filters[i].dst_ip6[j] = 0;
        }

        cfg->filters[i].do_min_len = 0;
        cfg->filters[i].min_len = 0;

        cfg->filters[i].do_max_len = 0;
        cfg->filters[i].max_len = 65535;

        cfg->filters[i].do_min_ttl = 0;
        cfg->filters[i].min_ttl = 0;

        cfg->filters[i].do_max_ttl = 0;
        cfg->filters[i].max_ttl = 255;

        cfg->filters[i].do_tos = 0;
        cfg->filters[i].tos = 0;

        cfg->filters[i].do_pps = 0;
        cfg->filters[i].pps = 0;
        
        cfg->filters[i].do_bps = 0;
        cfg->filters[i].bps = 0;

        cfg->filters[i].blocktime = 1;
        
        cfg->filters[i].tcpopts.enabled = 0;
        cfg->filters[i].tcpopts.do_dport = 0;
        cfg->filters[i].tcpopts.do_dport = 0;
        cfg->filters[i].tcpopts.do_urg = 0;
        cfg->filters[i].tcpopts.do_ack = 0;
        cfg->filters[i].tcpopts.do_rst = 0;
        cfg->filters[i].tcpopts.do_psh = 0;
        cfg->filters[i].tcpopts.do_syn = 0;
        cfg->filters[i].tcpopts.do_fin = 0;
        cfg->filters[i].tcpopts.do_ece = 0;
        cfg->filters[i].tcpopts.do_cwr = 0;

        cfg->filters[i].udpopts.enabled = 0;
        cfg->filters[i].udpopts.do_sport = 0;
        cfg->filters[i].udpopts.do_dport = 0;

        cfg->filters[i].icmpopts.enabled = 0;
        cfg->filters[i].icmpopts.do_code = 0;
        cfg->filters[i].icmpopts.do_type = 0;
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
 * 
 * @return 0 on success or 1/-1 on error.
 */
int ReadCfg(config__t *cfg)
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
        fprintf(stderr, "Error from LibConfig when reading file - %s (Line %d)\n\n", config_error_text(&conf), config_error_line(&conf));

        config_destroy(&conf);

        return EXIT_FAILURE;
    }

    int verbose;

    if (config_lookup_int(&conf, "verbose", &verbose) == CONFIG_TRUE)
    {
        cfg->verbose = verbose;
    }

    const char* log_file;

    if (config_lookup_string(&conf, "log_file", &log_file) == CONFIG_TRUE)
    {
        // We must free previous value to prevent memory leak.
        if (cfg->log_file != NULL)
        {
            free(cfg->log_file);
            cfg->log_file = NULL;
        }

        if (strlen(log_file) > 0)
        {
            cfg->log_file = strdup(log_file);
            
        }
        else
        {
            cfg->log_file = NULL;
        }
    }

    // Get interface.
    const char *interface;

    if (!config_lookup_string(&conf, "interface", &interface))
    {
        fprintf(stderr, "Error from LibConfig when reading 'interface' setting - %s\n\n", config_error_text(&conf));
        
        config_destroy(&conf);

        return EXIT_FAILURE;    
    }

    cfg->interface = strdup(interface);

    // Get auto update time.
    int updatetime;

    if (config_lookup_int(&conf, "update_time", &updatetime) == CONFIG_TRUE)
    {
        cfg->updatetime = updatetime;
    }

    // Get stdout update time.
    int stdout_update_time;

    if (config_lookup_int(&conf, "stdout_update_time", &stdout_update_time) == CONFIG_TRUE)
    {
        cfg->stdout_update_time = stdout_update_time;
    }

    // Get no stats.
    int nostats;

    if (config_lookup_bool(&conf, "no_stats", &nostats) == CONFIG_TRUE)
    {
        cfg->nostats = nostats;
    }

    // Read filters in filters_map structure.
    setting = config_lookup(&conf, "filters");

    // Check if filters map is valid. If not, not a biggie since they aren't required.
    if (setting == NULL)
    {
        fprintf(stderr, "Error from LibConfig when reading 'filters' array - %s\n\n", config_error_text(&conf));
        
        config_destroy(&conf);

        return 1;
    }

    // Set filter count.
    int filters = 0;

    for (int i = 0; i < config_setting_length(setting); i++)
    {
        config_setting_t* filter = config_setting_get_elem(setting, i);

        // Enabled.
        int enabled;

        if (config_setting_lookup_bool(filter, "enabled",  &enabled) == CONFIG_FALSE)
        {
            // Print error and stop from existing this rule any further.
            fprintf(stderr, "Error from LibConfig when reading 'enabled' setting from filters array #%d. Error - %s\n\n", filters, config_error_text(&conf));

            continue;
        }

        cfg->filters[i].enabled = enabled;

        // Action (required).
        int action;

        if (config_setting_lookup_int(filter, "action", &action) == CONFIG_FALSE)
        {
            fprintf(stderr, "Error from LibConfig when reading 'action' setting from filters array #%d. Error - %s\n\n", filters, config_error_text(&conf));

            cfg->filters[i].enabled = 0;

            continue;
        }

        cfg->filters[i].action = action;

        // Source IP (not required).
        const char *sip;

        if (config_setting_lookup_string(filter, "src_ip", &sip))
        {
            ip_range_t ip = ParseIpCidr(sip);

            cfg->filters[i].src_ip = ip.ip;
            cfg->filters[i].src_cidr = ip.cidr;
        }

        // Destination IP (not required).
        const char *dip;

        if (config_setting_lookup_string(filter, "dst_ip", &dip))
        {
            ip_range_t ip = ParseIpCidr(dip);

            cfg->filters[i].dst_ip = ip.ip;
            cfg->filters[i].dst_cidr = ip.cidr;
        }

        // Source IP (IPv6) (not required).
        const char *sip6;

        if (config_setting_lookup_string(filter, "src_ip6", &sip6))
        {
            struct in6_addr in;

            inet_pton(AF_INET6, sip6, &in);

            memcpy(cfg->filters[i].src_ip6, in.__in6_u.__u6_addr32, 4);
        }

        // Destination IP (IPv6) (not required).
        const char *dip6;

        if (config_setting_lookup_string(filter, "dst_ip6", &dip6))
        {
            struct in6_addr in;

            inet_pton(AF_INET6, dip6, &in);

            memcpy(cfg->filters[i].dst_ip6, in.__in6_u.__u6_addr32, 4);
        }

        // Minimum TTL (not required).
        int min_ttl;

        if (config_setting_lookup_int(filter, "min_ttl", &min_ttl))
        {
            cfg->filters[i].min_ttl = (u8)min_ttl;
            cfg->filters[i].do_min_ttl = 1;
        }

        // Maximum TTL (not required).
        int max_ttl;

        if (config_setting_lookup_int(filter, "max_ttl", &max_ttl))
        {
            cfg->filters[i].max_ttl = (u8)max_ttl;
            cfg->filters[i].do_max_ttl = 1;
        }

        // Minimum length (not required).
        int min_len;

        if (config_setting_lookup_int(filter, "min_len", &min_len))
        {
            cfg->filters[i].min_len = min_len;
            cfg->filters[i].do_min_len = 1;
        }

        // Maximum length (not required).
        int max_len;

        if (config_setting_lookup_int(filter, "max_len", &max_len))
        {
            cfg->filters[i].max_len = max_len;
            cfg->filters[i].do_max_len = 1;
        }

        // TOS (not required).
        int tos;

        if (config_setting_lookup_int(filter, "tos", &tos))
        {
            cfg->filters[i].tos = (u8)tos;
            cfg->filters[i].do_tos = 1;
        }

        // PPS (not required).
        long long pps;

        if (config_setting_lookup_int64(filter, "pps", &pps))
        {
            cfg->filters[i].pps = pps;
            cfg->filters[i].do_pps = 1;
        }

        // BPS (not required).
        long long bps;

        if (config_setting_lookup_int64(filter, "bps", &bps))
        {
            cfg->filters[i].bps = bps;
            cfg->filters[i].do_bps = 1;
        }

        // Block time (default 1).
        long long blocktime;

        if (config_setting_lookup_int64(filter, "block_time", &blocktime))
        {
            cfg->filters[i].blocktime = blocktime;
        }
        else
        {
            cfg->filters[i].blocktime = 1;
        }

        /* TCP options */
        // Enabled.
        int tcpenabled;

        if (config_setting_lookup_bool(filter, "tcp_enabled", &tcpenabled))
        {
            cfg->filters[i].tcpopts.enabled = tcpenabled;
        }

        // Source port.
        long long tcpsport;

        if (config_setting_lookup_int64(filter, "tcp_sport", &tcpsport))
        {
            cfg->filters[i].tcpopts.sport = (u16)tcpsport;
            cfg->filters[i].tcpopts.do_sport = 1;
        }

        // Destination port.
        long long tcpdport;

        if (config_setting_lookup_int64(filter, "tcp_dport", &tcpdport))
        {
            cfg->filters[i].tcpopts.dport = (u16)tcpdport;
            cfg->filters[i].tcpopts.do_dport = 1;
        }

        // URG flag.
        int tcpurg;

        if (config_setting_lookup_bool(filter, "tcp_urg", &tcpurg))
        {
            cfg->filters[i].tcpopts.urg = tcpurg;
            cfg->filters[i].tcpopts.do_urg = 1;
        }

        // ACK flag.
        int tcpack;

        if (config_setting_lookup_bool(filter, "tcp_ack", &tcpack))
        {
            cfg->filters[i].tcpopts.ack = tcpack;
            cfg->filters[i].tcpopts.do_ack = 1;
        }
        

        // RST flag.
        int tcprst;

        if (config_setting_lookup_bool(filter, "tcp_rst", &tcprst))
        {
            cfg->filters[i].tcpopts.rst = tcprst;
            cfg->filters[i].tcpopts.do_rst = 1;
        }

        // PSH flag.
        int tcppsh;

        if (config_setting_lookup_bool(filter, "tcp_psh", &tcppsh))
        {
            cfg->filters[i].tcpopts.psh = tcppsh;
            cfg->filters[i].tcpopts.do_psh = 1;
        }

        // SYN flag.
        int tcpsyn;

        if (config_setting_lookup_bool(filter, "tcp_syn", &tcpsyn))
        {
            cfg->filters[i].tcpopts.syn = tcpsyn;
            cfg->filters[i].tcpopts.do_syn = 1;
        }

        // FIN flag.
        int tcpfin;

        if (config_setting_lookup_bool(filter, "tcp_fin", &tcpfin))
        {
            cfg->filters[i].tcpopts.fin = tcpfin;
            cfg->filters[i].tcpopts.do_fin = 1;
        }

        // ECE flag.
        int tcpece;

        if (config_setting_lookup_bool(filter, "tcp_ece", &tcpece))
        {
            cfg->filters[i].tcpopts.ece = tcpece;
            cfg->filters[i].tcpopts.do_ece = 1;
        }

        // CWR flag.
        int tcpcwr;

        if (config_setting_lookup_bool(filter, "tcp_cwr", &tcpcwr))
        {
            cfg->filters[i].tcpopts.cwr = tcpcwr;
            cfg->filters[i].tcpopts.do_cwr = 1;
        }

        /* UDP options */
        // Enabled.
        int udpenabled;

        if (config_setting_lookup_bool(filter, "udp_enabled", &udpenabled))
        {
            cfg->filters[i].udpopts.enabled = udpenabled;
        }

        // Source port.
        long long udpsport;

        if (config_setting_lookup_int64(filter, "udp_sport", &udpsport))
        {
            cfg->filters[i].udpopts.sport = (u16)udpsport;
            cfg->filters[i].udpopts.do_sport = 1;
        }

        // Destination port.
        long long udpdport;

        if (config_setting_lookup_int64(filter, "udp_dport", &udpdport))
        {
            cfg->filters[i].udpopts.dport = (u16)udpdport;
            cfg->filters[i].udpopts.do_dport = 1;
        }

        /* ICMP options */
        // Enabled.
        int icmpenabled;

        if (config_setting_lookup_bool(filter, "icmp_enabled", &icmpenabled))
        {
            cfg->filters[i].icmpopts.enabled = icmpenabled;
        }

        // ICMP code.
        int icmpcode;

        if (config_setting_lookup_int(filter, "icmp_code", &icmpcode))
        {
            cfg->filters[i].icmpopts.code = (u8)icmpcode;
            cfg->filters[i].icmpopts.do_code = 1;
        }

        // ICMP type.
        int icmptype;

        if (config_setting_lookup_int(filter, "icmp_type", &icmptype))
        {
            cfg->filters[i].icmpopts.type = (u8)icmptype;
            cfg->filters[i].icmpopts.do_type = 1;
        }

        // Assign ID and increase filter count.
        cfg->filters[i].id = ++filters;
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
    fprintf(stdout, "Printing config...\n");
    fprintf(stdout, "\tGeneral Settings\n");
    fprintf(stdout, "\t\tInterface Name => %s\n", cfg->interface);
    fprintf(stdout, "\t\tUpdate Time => %d\n", cfg->updatetime);
    fprintf(stdout, "\t\tStdout Update Time => %d\n", cfg->stdout_update_time);
    fprintf(stdout, "\t\tNo Stats => %d\n\n", cfg->nostats);

    fprintf(stdout, "\tFilters\n");

    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_t *filter = &cfg->filters[i];

        if (filter->id < 1)
        {
            break;
        }

        fprintf(stdout, "\t\tFilter #%d:\n", (i + 1));

        // Main.
        fprintf(stdout, "\t\t\tID => %d\n", filter->id);
        fprintf(stdout, "\t\t\tEnabled => %d\n", filter->enabled);
        fprintf(stdout, "\t\t\tAction => %d (0 = Block, 1 = Allow).\n\n", filter->action);

        // IP Options.
        fprintf(stdout, "\t\t\tIP Options\n");

        // IP addresses require additional code for string printing.
        struct sockaddr_in sin;
        sin.sin_addr.s_addr = filter->src_ip;
        fprintf(stdout, "\t\t\t\tSource IPv4 => %s\n", inet_ntoa(sin.sin_addr));
        fprintf(stdout, "\t\t\t\tSource CIDR => %d\n", filter->src_cidr);

        struct sockaddr_in din;
        din.sin_addr.s_addr = filter->dst_ip;
        fprintf(stdout, "\t\t\t\tDestination IPv4 => %s\n", inet_ntoa(din.sin_addr));
        fprintf(stdout, "\t\t\t\tDestination CIDR => %d\n", filter->dst_cidr);

        struct in6_addr sin6;
        memcpy(&sin6, &filter->src_ip6, sizeof(sin6));
        
        char srcipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6, srcipv6, sizeof(srcipv6));

        fprintf(stdout, "\t\t\t\tSource IPv6 => %s\n", srcipv6);

        struct in6_addr din6;
        memcpy(&din6, &filter->dst_ip6, sizeof(din6));

        char dstipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &din6, dstipv6, sizeof(dstipv6));

        fprintf(stdout, "\t\t\t\tDestination IPv6 => %s\n", dstipv6);

        // Other IP header information.
        fprintf(stdout, "\t\t\t\tMax Length => %d\n", filter->max_len);
        fprintf(stdout, "\t\t\t\tMin Length => %d\n", filter->min_len);
        fprintf(stdout, "\t\t\t\tMax TTL => %d\n", filter->max_ttl);
        fprintf(stdout, "\t\t\t\tMin TTL => %d\n", filter->min_ttl);
        fprintf(stdout, "\t\t\t\tTOS => %d\n", filter->tos);
        fprintf(stdout, "\t\t\t\tPPS => %llu\n", filter->pps);
        fprintf(stdout, "\t\t\t\tBPS => %llu\n", filter->bps);
        fprintf(stdout, "\t\t\t\tBlock Time => %llu\n\n", filter->blocktime);

        // TCP Options.
        fprintf(stdout, "\t\t\tTCP Options\n");
        fprintf(stdout, "\t\t\t\tTCP Enabled => %d\n", filter->tcpopts.enabled);
        fprintf(stdout, "\t\t\t\tTCP Source Port => %d\n", filter->tcpopts.sport);
        fprintf(stdout, "\t\t\t\tTCP Destination Port => %d\n", filter->tcpopts.dport);
        fprintf(stdout, "\t\t\t\tTCP URG Flag => %d\n", filter->tcpopts.urg);
        fprintf(stdout, "\t\t\t\tTCP ACK Flag => %d\n", filter->tcpopts.ack);
        fprintf(stdout, "\t\t\t\tTCP RST Flag => %d\n", filter->tcpopts.rst);
        fprintf(stdout, "\t\t\t\tTCP PSH Flag => %d\n", filter->tcpopts.psh);
        fprintf(stdout, "\t\t\t\tTCP SYN Flag => %d\n", filter->tcpopts.syn);
        fprintf(stdout, "\t\t\t\tTCP FIN Flag => %d\n", filter->tcpopts.fin);
        fprintf(stdout, "\t\t\t\tTCP ECE Flag => %d\n", filter->tcpopts.ece);
        fprintf(stdout, "\t\t\t\tTCP CWR Flag => %d\n\n", filter->tcpopts.cwr);

        // UDP Options.
        fprintf(stdout, "\t\t\tUDP Options\n");
        fprintf(stdout, "\t\t\t\tUDP Enabled => %d\n", filter->udpopts.enabled);
        fprintf(stdout, "\t\t\t\tUDP Source Port => %d\n", filter->udpopts.sport);
        fprintf(stdout, "\t\t\t\tUDP Destination Port => %d\n\n", filter->udpopts.dport);

        // ICMP Options.
        fprintf(stdout, "\t\t\tICMP Options\n");
        fprintf(stdout, "\t\t\t\tICMP Enabled => %d\n", filter->icmpopts.enabled);
        fprintf(stdout, "\t\t\t\tICMP Code => %d\n", filter->icmpopts.code);
        fprintf(stdout, "\t\t\t\tICMP Type => %d\n", filter->icmpopts.type);

        fprintf(stdout, "\n\n");
    }
}