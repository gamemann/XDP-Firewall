#pragma once

#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <string.h>

#include <arpa/inet.h>

#include <loader/utils/helpers.h>

#define CONFIG_DEFAULT_PATH "/etc/xdpfw/xdpfw.conf"

struct config
{
    int verbose;
    char *log_file;
    char *interface;
    unsigned int pin_maps : 1;
    int update_time;
    unsigned int no_stats : 1;
    unsigned int stats_per_second : 1;
    int stdout_update_time;

    filter_t filters[MAX_FILTERS];
    const char* drop_ranges[MAX_IP_RANGES];
} typedef config__t; // config_t is taken by libconfig -.-

struct config_overrides
{
    int verbose;
    const char* log_file;
    const char* interface;
    int pin_maps;
    int update_time;
    int no_stats;
    int stats_per_second;
    int stdout_update_time;
} typedef config_overrides_t;

void set_cfg_defaults(config__t *cfg);
void set_filter_defaults(filter_t* filter);

void print_cfg(config__t* cfg);
void PrintFilter(filter_t* filter, int idx);

int load_cfg(config__t *cfg, const char* cfg_file, config_overrides_t* overrides);
int save_cfg(config__t* cfg, const char* file_path);

int open_cfg(FILE** file, const char *file_name);
int close_cfg(FILE* file);
int read_cfg(FILE* file, char** buffer);
int parse_cfg(config__t *cfg, const char* data, config_overrides_t* overrides);

int get_next_filter_idx(config__t* cfg);
int get_next_ip_drop_range_idx(config__t* cfg);

#include <loader/utils/logging.h>