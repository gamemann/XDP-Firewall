#include <loader/utils/config.h>

/**
 * Loads the config from the file system.
 * 
 * @param cfg A pointer to the config structure.
 * @param cfg_file The path to the config file.
 * @param overrides Overrides to use instead of config values.
 * 
 * @return 0 on success or 1 on error.
 */
int LoadConfig(config__t *cfg, const char* cfg_file, config_overrides_t* overrides)
{
    int ret;
    
    FILE *file = NULL;
    
    // Open config file.
    if ((ret = OpenCfg(&file, cfg_file)) != 0 || file == NULL)
    {
        fprintf(stderr, "Error opening config file.\n");
        
        return ret;
    }

    SetCfgDefaults(cfg);

    memset(cfg->filters, 0, sizeof(cfg->filters));

    char* buffer = NULL;

    // Read config.
    if ((ret = ReadCfg(file, &buffer)) != 0)
    {
        fprintf(stderr, "Error reading config file.\n");

        CloseCfg(file);

        return ret;
    }

    // Parse config.
    if ((ret = ParseCfg(cfg, buffer, overrides)) != 0)
    {
        fprintf(stderr, "Error parsing config file.\n");

        CloseCfg(file);

        return ret;
    }

    free(buffer);

    if ((ret = CloseCfg(file)) != 0)
    {
        fprintf(stderr, "Error closing config file.\n");

        return ret;
    }

    return EXIT_SUCCESS;
}

/**
 * Opens the config file.
 * 
 * @param file_name Path to config file.
 * 
 * @return 0 on success or 1 on error.
 */
int OpenCfg(FILE** file, const char *file_name)
{
    // Close any existing files.
    if (*file != NULL)
    {
        fclose(*file);

        *file = NULL;
    }

    *file = fopen(file_name, "r");

    if (*file == NULL)
    {
        return 1;
    }

    return 0;
}

/**
 * Close config file.
 * 
 * @param file A pointer to the file to close.
 * 
 * @param return 0 on success or error value of fclose().
 */
int CloseCfg(FILE* file)
{
    return fclose(file);
}

/**
 * Reads contents from the config file.
 * 
 * @param file The file pointer.
 * @param buffer The buffer to store the data in (manually allocated).
 */
int ReadCfg(FILE* file, char** buffer)
{
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    if (file_size <= 0)
    {
        return 1;
    }

    *buffer = malloc(file_size + 1);

    if (*buffer == NULL)
    {
        return 1;
    }

    size_t read = fread(*buffer, 1, file_size, file);
    (*buffer)[read] = '\0';

    return 0;
}

/**
 * Read the config file and stores values in config structure.
 * 
 * @param cfg A pointer to the config structure.
 * @param data The config data.
 * @param overrides Overrides to use instead of config values.
 * 
 * @return 0 on success or 1/-1 on error.
 */
int ParseCfg(config__t *cfg, const char* data, config_overrides_t* overrides)
{
    // Initialize config.
    config_t conf;
    config_setting_t *setting;

    config_init(&conf);

    // Attempt to read the config.
    if (config_read_string(&conf, data) == CONFIG_FALSE)
    {
        LogMsg(cfg, 0, 1, "Error from LibConfig when reading file - %s (Line %d)", config_error_text(&conf), config_error_line(&conf));

        config_destroy(&conf);

        return EXIT_FAILURE;
    }

    int verbose;

    if (config_lookup_int(&conf, "verbose", &verbose) == CONFIG_TRUE || (overrides && overrides->verbose > -1))
    {
        if (overrides && overrides->verbose > -1)
        {
            cfg->verbose = overrides->verbose;
        }
        else
        {
            cfg->verbose = verbose;
        }
    }

    const char* log_file;

    if (config_lookup_string(&conf, "log_file", &log_file) == CONFIG_TRUE || (overrides && overrides->log_file != NULL))
    {
        // We must free previous value to prevent memory leak.
        if (cfg->log_file != NULL)
        {
            free(cfg->log_file);
            cfg->log_file = NULL;
        }

        if (overrides && overrides->log_file != NULL)
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

    if (config_lookup_string(&conf, "interface", &interface) == CONFIG_TRUE || (overrides && overrides->interface != NULL))
    {
        // We must free previous value to prevent memory leak.
        if (cfg->interface != NULL)
        {
            free(cfg->interface);
            cfg->interface = NULL;
        }

        if (overrides && overrides->interface != NULL)
        {
            cfg->interface = strdup(overrides->interface);
        }
        else
        {
            cfg->interface = strdup(interface);
        }
    }

    // Pin BPF maps.
    int pin_maps;

    if (config_lookup_bool(&conf, "pin_maps", &pin_maps) == CONFIG_TRUE || (overrides && overrides->pin_maps > -1))
    {
        if (overrides && overrides->pin_maps > -1)
        {
            cfg->pin_maps = overrides->pin_maps;
        }
        else
        {
            cfg->pin_maps = pin_maps;
        }
    }

    // Get auto update time.
    int update_time;

    if (config_lookup_int(&conf, "update_time", &update_time) == CONFIG_TRUE || (overrides && overrides->update_time > -1))
    {
        if (overrides && overrides->update_time > -1)
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

    if (config_lookup_bool(&conf, "no_stats", &no_stats) == CONFIG_TRUE || (overrides && overrides->no_stats > -1))
    {
        if (overrides && overrides->no_stats > -1)
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

    if (config_lookup_bool(&conf, "stats_per_second", &stats_per_second) == CONFIG_TRUE || (overrides && overrides->stats_per_second > -1))
    {
        if (overrides && overrides->stats_per_second > -1)
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

    if (config_lookup_int(&conf, "stdout_update_time", &stdout_update_time) == CONFIG_TRUE || (overrides && overrides->stdout_update_time > -1))
    {
        if (overrides && overrides->stdout_update_time > -1)
        {
            cfg->stdout_update_time = overrides->stdout_update_time;
        }
        else
        {
            cfg->stdout_update_time = stdout_update_time;
        }
    }

    // Read filters.
    setting = config_lookup(&conf, "filters");

    if (setting && config_setting_is_list(setting))
    {
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
            int tcpsport;

            if (config_setting_lookup_int(filter_cfg, "tcp_sport", &tcpsport) == CONFIG_TRUE)
            {
                filter->tcpopts.sport = (u16)tcpsport;
                filter->tcpopts.do_sport = 1;
            }

            // Destination port.
            int tcpdport;

            if (config_setting_lookup_int(filter_cfg, "tcp_dport", &tcpdport) == CONFIG_TRUE)
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
            int udpsport;

            if (config_setting_lookup_int(filter_cfg, "udp_sport", &udpsport) == CONFIG_TRUE)
            {
                filter->udpopts.sport = (u16)udpsport;
                filter->udpopts.do_sport = 1;
            }

            // Destination port.
            int udpdport;

            if (config_setting_lookup_int(filter_cfg, "udp_dport", &udpdport) == CONFIG_TRUE)
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
    }

    // Read IP range drops.
    setting = config_lookup(&conf, "ip_drop_ranges");

    if (setting && config_setting_is_list(setting))
    {
        for (int i = 0; i < config_setting_length(setting) && i < MAX_IP_RANGES; i++)
        {
            const char* range = cfg->drop_ranges[i];

            if (cfg->drop_ranges[i])
            {
                free((void*)cfg->drop_ranges[i]);
                cfg->drop_ranges[i] = NULL;
            }

            const char* new_range = config_setting_get_string_elem(setting, i);

            if (new_range)
            {
                cfg->drop_ranges[i] = strdup(new_range);
            }
        }
    }

    config_destroy(&conf);

    return EXIT_SUCCESS;
}

/**
 * Saves config to file system.
 * 
 * @param cfg A pointer to the config.
 * @param file_path The file path to store the config into.
 * 
 * @param return 0 on success or 1 on failure.
 */
int SaveCfg(config__t* cfg, const char* file_path)
{
    config_t conf;
    config_setting_t *root, *setting;

    FILE* file;

    config_init(&conf);
    root = config_root_setting(&conf);

    // Add verbose.
    setting = config_setting_add(root, "verbose", CONFIG_TYPE_INT);
    config_setting_set_int(setting, cfg->verbose);

    // Add log file.
    if (cfg->log_file)
    {
        setting = config_setting_add(root, "log_file", CONFIG_TYPE_STRING);
        config_setting_set_string(setting, cfg->log_file);
    }

    // Add interface.
    if (cfg->interface)
    {
        setting = config_setting_add(root, "interface", CONFIG_TYPE_STRING);
        config_setting_set_string(setting, cfg->interface);
    }

    // Add pin maps.
    setting = config_setting_add(root, "pin_maps", CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, cfg->pin_maps);

    // Add update time.
    setting = config_setting_add(root, "update_time", CONFIG_TYPE_INT);
    config_setting_set_int(setting, cfg->update_time);

    // Add no stats.
    setting = config_setting_add(root, "no_stats", CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, cfg->no_stats);

    // Add stats per second.
    setting = config_setting_add(root, "stats_per_second", CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, cfg->stats_per_second);

    // Add stdout update time.
    setting = config_setting_add(root, "stdout_update_time", CONFIG_TYPE_INT);
    config_setting_set_int(setting, cfg->stdout_update_time);

    // Add filters.
    config_setting_t* filters = config_setting_add(root, "filters", CONFIG_TYPE_LIST);

    if (filters)
    {
        for (int i = 0; i < MAX_FILTERS; i++)
        {
            filter_t* filter = &cfg->filters[i];

            if (!filter->set)
            {
                continue;
            }

            config_setting_t* filter_cfg = config_setting_add(filters, NULL, CONFIG_TYPE_GROUP);

            if (filter_cfg)
            {
                // Add enabled setting.
                config_setting_t* enabled = config_setting_add(filter_cfg, "enabled", CONFIG_TYPE_BOOL);
                config_setting_set_bool(enabled, filter->enabled);

                // Add log setting.
                config_setting_t* log = config_setting_add(filter_cfg, "log", CONFIG_TYPE_BOOL);
                config_setting_set_bool(log, filter->log);

                // Add action setting.
                config_setting_t* action = config_setting_add(filter_cfg, "action", CONFIG_TYPE_INT);
                config_setting_set_int(action, filter->action);

                // Add source IPv4.
                if (filter->src_ip > 0)
                {
                    char ip_str[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &filter->src_ip, ip_str, sizeof(ip_str));

                    char full_ip[INET_ADDRSTRLEN + 6];
                    snprintf(full_ip, sizeof(full_ip), "%s/%d", ip_str, filter->src_cidr);

                    config_setting_t* src_ip = config_setting_add(filter_cfg, "src_ip", CONFIG_TYPE_STRING);
                    config_setting_set_string(src_ip, full_ip);
                }

                // Add destination IPv4.
                if (filter->dst_ip > 0)
                {
                    char ip_str[INET_ADDRSTRLEN];

                    inet_ntop(AF_INET, &filter->dst_ip, ip_str, sizeof(ip_str));

                    char full_ip[INET_ADDRSTRLEN + 6];
                    snprintf(full_ip, sizeof(full_ip), "%s/%d", ip_str, filter->src_cidr);

                    config_setting_t* dst_ip = config_setting_add(filter_cfg, "dst_ip", CONFIG_TYPE_STRING);
                    config_setting_set_string(dst_ip, full_ip);
                }
                
                // Add source IPv6.
                if (memcmp(filter->src_ip6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) != 0)
                {
                    char ip_str[INET6_ADDRSTRLEN];

                    inet_ntop(AF_INET, filter->src_ip6, ip_str, sizeof(ip_str));

                    //char full_ip[INET6_ADDRSTRLEN + 6];
                    //snprintf(full_ip, sizeof(full_ip), "%s/%d", ip_str, filter->src_cidr6);

                    config_setting_t* src_ip6 = config_setting_add(filter_cfg, "src_ip6", CONFIG_TYPE_STRING);
                    config_setting_set_string(src_ip6, ip_str);
                }

                // Add source IPv6.
                if (memcmp(filter->dst_ip6, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) != 0)
                {
                    char ip_str[INET6_ADDRSTRLEN];

                    inet_ntop(AF_INET, filter->dst_ip6, ip_str, sizeof(ip_str));

                    //char full_ip[INET6_ADDRSTRLEN + 6];
                    //snprintf(full_ip, sizeof(full_ip), "%s/%d", ip_str, filter->src_cidr6);

                    config_setting_t* dst_ip6 = config_setting_add(filter_cfg, "dst_ip6", CONFIG_TYPE_STRING);
                    config_setting_set_string(dst_ip6, ip_str);
                }

                // Add minimum TTL.
                config_setting_t* min_ttl = config_setting_add(filter_cfg, "min_ttl", CONFIG_TYPE_INT);
                config_setting_set_int(min_ttl, filter->min_ttl);

                // Add maximum TTL.
                config_setting_t* max_ttl = config_setting_add(filter_cfg, "max_ttl", CONFIG_TYPE_INT);
                config_setting_set_int(max_ttl, filter->max_ttl);

                // Add minimum length.
                config_setting_t* min_len = config_setting_add(filter_cfg, "min_len", CONFIG_TYPE_INT);
                config_setting_set_int(min_len, filter->min_len);

                // Add maximum length.
                config_setting_t* max_len = config_setting_add(filter_cfg, "max_len", CONFIG_TYPE_INT);
                config_setting_set_int(max_len, filter->max_len);

                // Add ToS.
                config_setting_t* tos = config_setting_add(filter_cfg, "tos", CONFIG_TYPE_INT);
                config_setting_set_int(tos, filter->tos);

                // Add PPS.
                config_setting_t* pps = config_setting_add(filter_cfg, "pps", CONFIG_TYPE_INT64);
                config_setting_set_int64(pps, filter->pps);

                // Add BPS.
                config_setting_t* bps = config_setting_add(filter_cfg, "bps", CONFIG_TYPE_INT64);
                config_setting_set_int64(bps, filter->bps);

                // Add block time.
                config_setting_t* block_time = config_setting_add(filter_cfg, "block_time", CONFIG_TYPE_INT64);
                config_setting_set_int64(block_time, filter->block_time);

                // Add TCP enabled.
                config_setting_t* tcp_enabled = config_setting_add(filter_cfg, "tcp_enabled", CONFIG_TYPE_BOOL);
                config_setting_set_bool(tcp_enabled, filter->tcpopts.enabled);

                // Add TCP source port.
                config_setting_t* tcp_sport = config_setting_add(filter_cfg, "tcp_sport", CONFIG_TYPE_INT);
                config_setting_set_int(tcp_sport, filter->tcpopts.sport);

                // Add TCP destination port.
                config_setting_t* tcp_dport = config_setting_add(filter_cfg, "tcp_dport", CONFIG_TYPE_INT);
                config_setting_set_int(tcp_dport, filter->tcpopts.dport);

                // Add TCP URG flag.
                config_setting_t* tcp_urg = config_setting_add(filter_cfg, "tcp_urg", CONFIG_TYPE_BOOL);
                config_setting_set_bool(tcp_urg, filter->tcpopts.urg);

                // Add TCP ACK flag.
                config_setting_t* tcp_ack = config_setting_add(filter_cfg, "tcp_ack", CONFIG_TYPE_BOOL);
                config_setting_set_bool(tcp_ack, filter->tcpopts.ack);

                // Add TCP RST flag.
                config_setting_t* tcp_rst = config_setting_add(filter_cfg, "tcp_rst", CONFIG_TYPE_BOOL);
                config_setting_set_bool(tcp_rst, filter->tcpopts.rst);

                // Add TCP PSH flag.
                config_setting_t* tcp_psh = config_setting_add(filter_cfg, "tcp_psh", CONFIG_TYPE_BOOL);
                config_setting_set_bool(tcp_psh, filter->tcpopts.psh);

                // Add TCP SYN flag.
                config_setting_t* tcp_syn = config_setting_add(filter_cfg, "tcp_syn", CONFIG_TYPE_BOOL);
                config_setting_set_bool(tcp_syn, filter->tcpopts.syn);

                // Add TCP FIN flag.
                config_setting_t* tcp_fin = config_setting_add(filter_cfg, "tcp_fin", CONFIG_TYPE_BOOL);
                config_setting_set_bool(tcp_fin, filter->tcpopts.fin);

                // Add TCP ECE flag.
                config_setting_t* tcp_ece = config_setting_add(filter_cfg, "tcp_ece", CONFIG_TYPE_BOOL);
                config_setting_set_bool(tcp_ece, filter->tcpopts.ece);

                // Add TCP CWR flag.
                config_setting_t* tcp_cwr = config_setting_add(filter_cfg, "tcp_cwr", CONFIG_TYPE_BOOL);
                config_setting_set_bool(tcp_cwr, filter->tcpopts.cwr);

                // Add UDP enabled.
                config_setting_t* udp_enabled = config_setting_add(filter_cfg, "udp_enabled", CONFIG_TYPE_BOOL);
                config_setting_set_bool(udp_enabled, filter->udpopts.enabled);

                // Add UDP source port.
                config_setting_t* udp_sport = config_setting_add(filter_cfg, "udp_sport", CONFIG_TYPE_INT);
                config_setting_set_int(udp_sport, filter->udpopts.sport);

                // Add UDP destination port.
                config_setting_t* udp_dport = config_setting_add(filter_cfg, "udp_dport", CONFIG_TYPE_INT);
                config_setting_set_int(udp_dport, filter->udpopts.dport);

                // Add ICMP enabled.
                config_setting_t* icmp_enabled = config_setting_add(filter_cfg, "icmp_enabled", CONFIG_TYPE_BOOL);
                config_setting_set_bool(icmp_enabled, filter->icmpopts.enabled);

                // Add ICMP code.
                config_setting_t* icmp_code = config_setting_add(filter_cfg, "icmp_code", CONFIG_TYPE_INT);
                config_setting_set_int(icmp_code, filter->icmpopts.code);

                // Add ICMP type.
                config_setting_t* icmp_type = config_setting_add(filter_cfg, "icmp_type", CONFIG_TYPE_INT);
                config_setting_set_int(icmp_type, filter->icmpopts.type);
            }
        }
    }

    // Add IP ranges.
    config_setting_t* ip_drop_ranges = config_setting_add(root, "ip_drop_ranges", CONFIG_TYPE_LIST);

    if (ip_drop_ranges)
    {
        for (int i = 0; i < MAX_IP_RANGES; i++)
        {
            const char* range = cfg->drop_ranges[i];

            if (range)
            {
                config_setting_t* elem = config_setting_add(ip_drop_ranges, NULL, CONFIG_TYPE_STRING);

                if (elem)
                {
                    config_setting_set_string(elem, range);
                }
            }
        }
    }

    // Write config to file.
    file = fopen(file_path, "w");

    if (!file)
    {
        config_destroy(&conf);

        return 1;
    }

    config_write(&conf, file);

    fclose(file);
    config_destroy(&conf);

    return 0;
}

/**
 * Sets the default values for a filter.
 * 
 * @param filter A pointer to the filter.
 * 
 * @return void
 */
void SetFilterDefaults(filter_t* filter)
{
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

/**
 * Sets the config structure's default values.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return void
 */
void SetCfgDefaults(config__t* cfg)
{
    cfg->verbose = 2;
    cfg->log_file = strdup("/var/log/xdpfw.log");
    cfg->update_time = 0;
    cfg->interface = NULL;
    cfg->pin_maps = 1;
    cfg->no_stats = 0;
    cfg->stats_per_second = 0;
    cfg->stdout_update_time = 1000;

    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_t* filter = &cfg->filters[i];

        SetFilterDefaults(filter);
    }

    memset(cfg->drop_ranges, 0, sizeof(cfg->drop_ranges));
}

/**
 * Prints a filter rule.
 * 
 * @param filter A pointer to the filter rule.
 * @param idx The current index.
 * 
 * @return void
 */
void PrintFilter(filter_t* filter, int idx)
{
    printf("\tFilter #%d\n", idx);
    printf("\t\tEnabled => %d\n", filter->enabled);
    printf("\t\tAction => %d (0 = Block, 1 = Allow).\n", filter->action);
    printf("\t\tLog => %d\n\n", filter->log);

    // IP Options.
    printf("\t\tIP Options\n");

    // IP addresses require additional code for string printing.
    struct sockaddr_in sin;
    sin.sin_addr.s_addr = filter->src_ip;
    printf("\t\t\tSource IPv4 => %s\n", inet_ntoa(sin.sin_addr));
    printf("\t\t\tSource CIDR => %d\n", filter->src_cidr);

    struct sockaddr_in din;
    din.sin_addr.s_addr = filter->dst_ip;
    printf("\t\t\tDestination IPv4 => %s\n", inet_ntoa(din.sin_addr));
    printf("\t\t\tDestination CIDR => %d\n", filter->dst_cidr);

    struct in6_addr sin6;
    memcpy(&sin6, &filter->src_ip6, sizeof(sin6));
    
    char srcipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &sin6, srcipv6, sizeof(srcipv6));

    printf("\t\t\tSource IPv6 => %s\n", srcipv6);

    struct in6_addr din6;
    memcpy(&din6, &filter->dst_ip6, sizeof(din6));

    char dstipv6[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &din6, dstipv6, sizeof(dstipv6));

    printf("\t\t\tDestination IPv6 => %s\n", dstipv6);

    // Other IP header information.
    printf("\t\t\tMax Length => %d\n", filter->max_len);
    printf("\t\t\tMin Length => %d\n", filter->min_len);
    printf("\t\t\tMax TTL => %d\n", filter->max_ttl);
    printf("\t\t\tMin TTL => %d\n", filter->min_ttl);
    printf("\t\t\tTOS => %d\n", filter->tos);
    printf("\t\t\tPPS => %llu\n", filter->pps);
    printf("\t\t\tBPS => %llu\n", filter->bps);
    printf("\t\t\tBlock Time => %llu\n\n", filter->block_time);

    // TCP Options.
    printf("\t\tTCP Options\n");
    printf("\t\t\tTCP Enabled => %d\n", filter->tcpopts.enabled);
    printf("\t\t\tTCP Source Port => %d\n", filter->tcpopts.sport);
    printf("\t\t\tTCP Destination Port => %d\n", filter->tcpopts.dport);
    printf("\t\t\tTCP URG Flag => %d\n", filter->tcpopts.urg);
    printf("\t\t\tTCP ACK Flag => %d\n", filter->tcpopts.ack);
    printf("\t\t\tTCP RST Flag => %d\n", filter->tcpopts.rst);
    printf("\t\t\tTCP PSH Flag => %d\n", filter->tcpopts.psh);
    printf("\t\t\tTCP SYN Flag => %d\n", filter->tcpopts.syn);
    printf("\t\t\tTCP FIN Flag => %d\n", filter->tcpopts.fin);
    printf("\t\t\tTCP ECE Flag => %d\n", filter->tcpopts.ece);
    printf("\t\t\tTCP CWR Flag => %d\n\n", filter->tcpopts.cwr);

    // UDP Options.
    printf("\t\tUDP Options\n");
    printf("\t\t\tUDP Enabled => %d\n", filter->udpopts.enabled);
    printf("\t\t\tUDP Source Port => %d\n", filter->udpopts.sport);
    printf("\t\t\tUDP Destination Port => %d\n\n", filter->udpopts.dport);

    // ICMP Options.
    printf("\t\tICMP Options\n");
    printf("\t\t\tICMP Enabled => %d\n", filter->icmpopts.enabled);
    printf("\t\t\tICMP Code => %d\n", filter->icmpopts.code);
    printf("\t\t\tICMP Type => %d\n", filter->icmpopts.type);
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
    printf("General Settings\n");
    
    printf("\tVerbose => %d\n", cfg->verbose);
    printf("\tLog File => %s\n", log_file);
    printf("\tInterface Name => %s\n", interface);
    printf("\tPin BPF Maps => %d\n", cfg->pin_maps);
    printf("\tUpdate Time => %d\n", cfg->update_time);
    printf("\tNo Stats => %d\n", cfg->no_stats);
    printf("\tStats Per Second => %d\n", cfg->stats_per_second);
    printf("\tStdout Update Time => %d\n\n", cfg->stdout_update_time);

    printf("Filters\n");

    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_t *filter = &cfg->filters[i];

        if (!filter->set)
        {
            break;
        }

        PrintFilter(filter, i + 1);

        printf("\n\n");
    }

    printf("\n");

    printf("IP Drop Ranges\n");

    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        const char* range = cfg->drop_ranges[i];

        if (range)
        {
            printf("\t- %s\n", range);
        }
    }
}

/**
 * Retrieves next available filter index.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return The next available index or -1 if there are no available indexes.
 */
int GetNextAvailableFilterIndex(config__t* cfg)
{
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        filter_t* filter = &cfg->filters[i];

        if (filter->set)
        {
            continue;
        }

        return i;
    }

    return -1;
}

/**
 * Retrieves the next available IP drop range index.
 * 
 * @param cfg A pointer to the config structure.
 * 
 * @return The next available index or -1 if there are no available indexes.
 */
int GetNextAvailableIpDropRangeIndex(config__t* cfg)
{
    for (int i = 0; i < MAX_IP_RANGES; i++)
    {
        const char* range = cfg->drop_ranges[i];

        if (range)
        {
            continue;
        }

        return i;
    }

    return -1;
}