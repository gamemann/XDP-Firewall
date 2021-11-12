#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <string.h>

#include <arpa/inet.h>

#include "xdpfw.h"
#include "config.h"

FILE *file;

void setcfgdefaults(struct config *cfg)
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

        for (uint8_t j = 0; j < 4; j++)
        {
            cfg->filters[i].srcIP6[j] = 0;
            cfg->filters[i].dstIP6[j] = 0;
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

        cfg->filters[i].blockTime = 1;
        
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
    }
}

int opencfg(const char *FileName)
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

int readcfg(struct config *cfg)
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

        // Source IP (IPv6) (not required).
        const char *sIP6;

        if (config_setting_lookup_string(filter, "srcip6", &sIP6))
        {
            struct in6_addr in;

            inet_pton(AF_INET6, sIP6, &in);

            for (uint8_t j = 0; j < 4; j++)
            {
                cfg->filters[i].srcIP6[j] = in.__in6_u.__u6_addr32[j];
            }
        }

        // Destination IP (IPv6) (not required).
        const char *dIP6;

        if (config_setting_lookup_string(filter, "dstip6", &dIP6))
        {
            struct in6_addr in;

            inet_pton(AF_INET6, dIP6, &in);

            for (uint8_t j = 0; j < 4; j++)
            {
                cfg->filters[i].dstIP6[j] = in.__in6_u.__u6_addr32[j];
            }
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

        // Block time (default 1).
        long long blocktime;

        if (config_setting_lookup_int64(filter, "blocktime", &blocktime))
        {
            cfg->filters[i].blockTime = blocktime;
        }
        else
        {
            cfg->filters[i].blockTime = 1;
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
            cfg->filters[i].tcpopts.sport = (uint16_t)tcpsport;
            cfg->filters[i].tcpopts.do_sport = 1;
        }

        // Destination port.
        long long tcpdport;

        if (config_setting_lookup_int64(filter, "tcp_dport", &tcpdport))
        {
            cfg->filters[i].tcpopts.dport = (uint16_t)tcpdport;
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
            cfg->filters[i].udpopts.sport = (uint16_t)udpsport;
            cfg->filters[i].udpopts.do_sport = 1;
        }

        // Destination port.
        long long udpdport;

        if (config_setting_lookup_int64(filter, "udp_dport", &udpdport))
        {
            cfg->filters[i].udpopts.dport = (uint16_t)udpdport;
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
            cfg->filters[i].icmpopts.code = (uint8_t)icmpcode;
            cfg->filters[i].icmpopts.do_code = 1;
        }

        // ICMP type.
        int icmptype;

        if (config_setting_lookup_int(filter, "icmp_type", &icmptype))
        {
            cfg->filters[i].icmpopts.type = (uint8_t)icmptype;
            cfg->filters[i].icmpopts.do_type = 1;
        }

        // Assign ID.
        cfg->filters[i].id = filters + 1;

        // Increase filter count.
        filters++;
    }

    config_destroy(&conf);

    return 0;
}