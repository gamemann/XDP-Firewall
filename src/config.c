#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <string.h>

#include <arpa/inet.h>

#include "include/xdpfw.h"
#include "include/config.h"

FILE *file;

void SetConfigDefaults(struct config_map *cfg)
{
    cfg->updateTime = 0;
    cfg->interface = "eth0";
    cfg->nostats = 0;

    for (uint16_t i = 0; i < MAX_FILTERS; i++)
    {
        cfg->filters[i].id = 0;
        cfg->filters[i].enabled = 0;
        cfg->filters[i].action = 0;
        cfg->filters[i].srcIP = 0;
        cfg->filters[i].dstIP = 0;

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
        
        cfg->filters[i].tcpopts.enabled = 0;
        cfg->filters[i].tcpopts.do_dport = 0;
        cfg->filters[i].tcpopts.do_dport = 0;
        cfg->filters[i].tcpopts.do_urg = 0;
        cfg->filters[i].tcpopts.do_ack = 0;
        cfg->filters[i].tcpopts.do_rst = 0;
        cfg->filters[i].tcpopts.do_psh = 0;
        cfg->filters[i].tcpopts.do_syn = 0;
        cfg->filters[i].tcpopts.do_fin = 0;

        cfg->filters[i].udpopts.enabled = 0;
        cfg->filters[i].udpopts.do_sport = 0;
        cfg->filters[i].udpopts.do_dport = 0;

        cfg->filters[i].icmpopts.enabled = 0;
        cfg->filters[i].icmpopts.do_code = 0;
        cfg->filters[i].icmpopts.do_type = 0;

        for (uint16_t j = 0; j < MAX_PCKT_LENGTH - 1; j++)
        {
            cfg->filters[i].payloadMatch[j] = 0;
        }

        cfg->filters[i].payloadLen = 0;
    }
}

int OpenConfig(const char *FileName)
{
    // Close any existing files.
    if (file != NULL)
    {
        fclose(file);

        file = NULL;
    }

    file = fopen(FileName, "r");

    if (file == NULL)
    {
        return 1;
    }

    return 0;
}

int ReadConfig(struct config_map *cfg)
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

        return 1;
    }

    // Get interface.
    const char *interface;

    if (!config_lookup_string(&conf, "interface", &interface))
    {
        fprintf(stderr, "Error from LibConfig when reading 'interface' setting - %s\n\n", config_error_text(&conf));
        
        config_destroy(&conf);

        return 1;    
    }

    cfg->interface = strdup(interface);

    // Get auto update time.
    int updateTime;

    if (!config_lookup_int(&conf, "updatetime", &updateTime))
    {
        fprintf(stderr, "Error from LibConfig when reading 'updatetime' setting - %s\n\n", config_error_text(&conf));
        
        config_destroy(&conf);

        return 1;    
    }

    cfg->updateTime = updateTime;

    // Get no stats.
    int nostats;

    if (config_lookup_bool(&conf, "nostats", &nostats) == CONFIG_TRUE)
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

    for (uint8_t i = 0; i < config_setting_length(setting); i++)
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
        const char *sIP;

        if (config_setting_lookup_string(filter, "srcip", &sIP))
        {
            cfg->filters[i].srcIP = inet_addr(sIP);
        }

        // Destination IP (not required).
        const char *dIP;

        if (config_setting_lookup_string(filter, "dstip", &dIP))
        {
            cfg->filters[i].dstIP = inet_addr(dIP);
        }

        // Minimum TTL (not required).
        int min_ttl;

        if (config_setting_lookup_int(filter, "min_ttl", &min_ttl))
        {
            cfg->filters[i].min_ttl = (uint8_t)min_ttl;
            cfg->filters[i].do_min_ttl = 1;
        }

        // Maximum TTL (not required).
        int max_ttl;

        if (config_setting_lookup_int(filter, "max_ttl", &max_ttl))
        {
            cfg->filters[i].max_ttl = (uint8_t)max_ttl;
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
            cfg->filters[i].tos = (uint8_t)tos;
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

        // Payload match.
        const char *payload;

        if (config_setting_lookup_string(filter, "payloadmatch", &payload))
        {
            // We need to split the string and scan everything into the uint8_t payload.
            char *split;

            char *str = malloc((strlen(payload) + 1) * sizeof(char));
            strcpy(str, payload);

            split = strtok(str, " ");

            while (split != NULL)
            {
                sscanf(split, "%2hhx", &cfg->filters[i].payloadMatch[cfg->filters[i].payloadLen]);

                cfg->filters[i].payloadLen++;

                split = strtok(NULL, " ");
            }
        }

        // Check for TCP options.
        config_setting_t* tcpopts = config_setting_lookup(filter, "tcpopts");
        
        // Check TCP options.
        if (tcpopts != NULL)
        {
            for (uint16_t j = 0; j < config_setting_length(tcpopts); j++)
            {
                config_setting_t* tcp = config_setting_get_elem(tcpopts, j);

                // Enabled.
                int enabled;

                if (config_setting_lookup_bool(tcp, "enabled", &enabled))
                {
                    cfg->filters[i].tcpopts.enabled = enabled;
                }

                // Source port.
                long long sport;

                if (config_setting_lookup_int64(tcp, "sport", &sport))
                {
                    cfg->filters[i].tcpopts.sport = (uint16_t)sport;
                    cfg->filters[i].tcpopts.do_sport = 1;
                }

                // Destination port.
                long long dport;

                if (config_setting_lookup_int64(tcp, "dport", &dport))
                {
                    cfg->filters[i].tcpopts.dport = (uint16_t)dport;
                    cfg->filters[i].tcpopts.do_dport = 1;
                }

                // URG flag.
                int urg;

                if (config_setting_lookup_bool(tcp, "urg", &urg))
                {
                    cfg->filters[i].tcpopts.urg = urg;
                    cfg->filters[i].tcpopts.do_urg = 1;
                }

                // ACK flag.
                int ack;

                if (config_setting_lookup_bool(tcp, "ack", &ack))
                {
                    cfg->filters[i].tcpopts.ack = ack;
                    cfg->filters[i].tcpopts.do_ack = 1;
                }

                // RST flag.
                int rst;

                if (config_setting_lookup_bool(tcp, "rst", &rst))
                {
                    cfg->filters[i].tcpopts.rst = rst;
                    cfg->filters[i].tcpopts.do_rst = 1;
                }

                // PSH flag.
                int psh;

                if (config_setting_lookup_bool(tcp, "psh", &psh))
                {
                    cfg->filters[i].tcpopts.psh = psh;
                    cfg->filters[i].tcpopts.do_psh = 1;
                }

                // SYN flag.
                int syn;

                if (config_setting_lookup_bool(tcp, "syn", &syn))
                {
                    cfg->filters[i].tcpopts.syn = syn;
                    cfg->filters[i].tcpopts.do_syn = 1;
                }

                // FIN flag.
                int fin;

                if (config_setting_lookup_bool(tcp, "fin", &fin))
                {
                    cfg->filters[i].tcpopts.fin = fin;
                    cfg->filters[i].tcpopts.do_fin = 1;
                }
            }
        }

        // Check for UDP options.
        config_setting_t* udpopts = config_setting_lookup(filter, "udpopts");
        
        // Check UDP options.
        if (udpopts != NULL)
        {
            for (uint16_t j = 0; j < config_setting_length(udpopts); j++)
            {
                config_setting_t* udp = config_setting_get_elem(udpopts, j);

                // Enabled.
                int enabled;

                if (config_setting_lookup_bool(udp, "enabled", &enabled))
                {
                    cfg->filters[i].udpopts.enabled = enabled;
                }

                // Source port.
                long long sport;

                if (config_setting_lookup_int64(udp, "sport", &sport))
                {
                    cfg->filters[i].udpopts.sport = (uint16_t)sport;
                    cfg->filters[i].udpopts.do_sport = 1;
                }

                // Destination port.
                long long dport;

                if (config_setting_lookup_int64(udp, "dport", &dport))
                {
                    cfg->filters[i].udpopts.dport = (uint16_t)dport;
                    cfg->filters[i].udpopts.do_dport = 1;
                }
            }
        }

        // Check for ICMP options.
        config_setting_t* icmpopts = config_setting_lookup(filter, "icmpopts");
        
        // Check UDP options.
        if (icmpopts != NULL)
        {
            for (uint16_t j = 0; j < config_setting_length(icmpopts); j++)
            {
                config_setting_t* icmp = config_setting_get_elem(icmpopts, j);
                
                // Enabled.
                int enabled;

                if (config_setting_lookup_bool(icmp, "enabled", &enabled))
                {
                    cfg->filters[i].icmpopts.enabled = enabled;
                }

                // ICMP code.
                int code;

                if (config_setting_lookup_int(icmp, "code", &code))
                {
                    cfg->filters[i].icmpopts.code = (uint8_t)code;
                    cfg->filters[i].icmpopts.do_code = 1;
                }

                // ICMP type.
                int type;

                if (config_setting_lookup_int(icmp, "type", &type))
                {
                    cfg->filters[i].icmpopts.type = (uint8_t)type;
                    cfg->filters[i].icmpopts.do_type = 1;
                }
            }
        }

        // Assign ID.
        cfg->filters[i].id = filters + 1;

        // Increase filter count.
        filters++;
    }

    config_destroy(&conf);

    return 0;
}