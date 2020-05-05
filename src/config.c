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

    for (uint16_t i = 0; i < MAX_FILTERS; i++)
    {
        cfg->filters[i].enabled = 0;
        cfg->filters[i].action = 0;
        cfg->filters[i].srcIP = 0;
        cfg->filters[i].dstIP = 0;
        cfg->filters[i].min_id = 0;
        cfg->filters[i].max_id = 4294967295;
        cfg->filters[i].min_len = 0;
        cfg->filters[i].max_len = 65535;
        cfg->filters[i].min_ttl = 0;
        cfg->filters[i].max_ttl = 255;
        cfg->filters[i].tos = 0;
        cfg->filters[i].protocol = 0;
        
        cfg->filters[i].tcpopts.enabled = 0;
        cfg->filters[i].udpopts.enabled = 0;
        cfg->filters[i].icmpopts.enabled = 0;

        for (uint16_t j = 0; i < MAX_PCKT_LENGTH; i++)
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

    if (!config_lookup_bool(&conf, "updatetime", &updateTime))
    {
        fprintf(stderr, "Error from LibConfig when reading 'updatetime' setting - %s\n\n", config_error_text(&conf));
        
        config_destroy(&conf);

        return 1;    
    }

    cfg->updateTime = updateTime;

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

        if (config_setting_lookup_bool(filter, "enabled",  &enabled) != 0)
        {
            // Print error and stop from existing this rule any further.
            fprintf(stderr, "Error from LibConfig when reading 'enabled' setting from filters array #%d. Error - %s\n\n", filters, config_error_text(&conf));

            continue;
        }

        cfg->filters[i].enabled = enabled;

        // Action (required).
        int action;

        if (config_setting_lookup_int(filter, "action", &action) != 0)
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

        // Protocol (required).
        int protocol;

        if (!config_setting_lookup_int(filter, "protocol", &protocol))
        {
            fprintf(stderr, "Error from LibConfig when reading 'protocol' setting from filters array #%d. Error - %s\n\n", filters, config_error_text(&conf));

            cfg->filters[i].enabled = 0;

            continue;
        }

        cfg->filters[i].protocol = protocol;

        // Minimum TTL (not required).
        int min_ttl;

        if (config_setting_lookup_int(filter, "min_ttl", &min_ttl))
        {
            cfg->filters[i].min_ttl = min_ttl;
        }

        // Maximum TTL (not required).
        int max_ttl;

        if (config_setting_lookup_int(filter, "max_ttl", &max_ttl))
        {
            cfg->filters[i].max_ttl = max_ttl;
        }

        // Minimum length (not required).
        int min_len;

        if (config_setting_lookup_int(filter, "min_len", &min_len))
        {
            cfg->filters[i].min_len = min_len;
        }

        // Maximum length (not required).
        int max_len;

        if (config_setting_lookup_int(filter, "max_len", &max_len))
        {
            cfg->filters[i].max_len = max_len;
        }

        // TOS (not required).
        int tos;

        if (config_setting_lookup_int(filter, "tos", &tos))
        {
            cfg->filters[i].tos = tos;
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
            // Enabled.
            int enabled;

            if (config_setting_lookup_bool(tcpopts, "enabled", &enabled))
            {
                cfg->filters[i].tcpopts.enabled = enabled;
            }

            // Source port.
            long long sport;

            if (config_setting_lookup_int64(tcpopts, "sport", &sport))
            {
                cfg->filters[i].tcpopts.sport = (uint16_t)sport;
            }

            // Destination port.
            long long dport;

            if (config_setting_lookup_int64(tcpopts, "dport", &dport))
            {
                cfg->filters[i].tcpopts.dport = (uint16_t)dport;
            }

            // URG flag.
            int urg;

            if (config_setting_lookup_bool(tcpopts, "urg", &urg))
            {
                cfg->filters[i].tcpopts.urg = urg;
            }

            // ACK flag.
            int ack;

            if (config_setting_lookup_bool(tcpopts, "ack", &ack))
            {
                cfg->filters[i].tcpopts.ack = ack;
            }

            // RST flag.
            int rst;

            if (config_setting_lookup_bool(tcpopts, "rst", &rst))
            {
                cfg->filters[i].tcpopts.rst = rst;
            }

            // PSH flag.
            int psh;

            if (config_setting_lookup_bool(tcpopts, "psh", &psh))
            {
                cfg->filters[i].tcpopts.psh = psh;
            }

            // SYN flag.
            int syn;

            if (config_setting_lookup_bool(tcpopts, "syn", &syn))
            {
                cfg->filters[i].tcpopts.syn = syn;
            }

            // FIN flag.
            int fin;

            if (config_setting_lookup_bool(tcpopts, "fin", &fin))
            {
                cfg->filters[i].tcpopts.fin = fin;
            }
        }

        // Check for UDP options.
        config_setting_t* udpopts = config_setting_lookup(filter, "udpopts");
        
        // Check UDP options.
        if (udpopts != NULL)
        {
            // Enabled.
            int enabled;

            if (config_setting_lookup_bool(udpopts, "enabled", &enabled))
            {
                cfg->filters[i].udpopts.enabled = enabled;
            }

            // Source port.
            long long sport;

            if (config_setting_lookup_int64(udpopts, "sport", &sport))
            {
                cfg->filters[i].udpopts.sport = (uint16_t)sport;
            }

            // Destination port.
            long long dport;

            if (config_setting_lookup_int64(udpopts, "dport", &dport))
            {
                cfg->filters[i].udpopts.dport = (uint16_t)dport;
            }
        }

        // Check for ICMP options.
        config_setting_t* icmpopts = config_setting_lookup(filter, "icmpopts");
        
        // Check UDP options.
        if (icmpopts != NULL)
        {
            // Enabled.
            int enabled;

            if (config_setting_lookup_bool(icmpopts, "enabled", &enabled))
            {
                cfg->filters[i].icmpopts.enabled = enabled;
            }

            // ICMP code.
            int code;

            if (config_setting_lookup_int(icmpopts, "code", &code))
            {
                cfg->filters[i].icmpopts.code = code;
            }

            // ICMP type.
            int type;

            if (config_setting_lookup_int(icmpopts, "type", &type))
            {
                cfg->filters[i].icmpopts.type = type;
            }
        }
        
        // Increase filter count.
        filters++;
    }

    // Assign filter count to config.
    cfg->filterCount = filters;

    config_destroy(&conf);

    return 0;
}