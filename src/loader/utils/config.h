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

void SetCfgDefaults(config__t *cfg);

void PrintFilter(filter_t* filter, int idx);
void PrintConfig(config__t* cfg);

int LoadConfig(config__t *cfg, char *cfg_file, config_overrides_t* overrides);
int SaveCfg(config__t* cfg, const char* file_path);

int OpenCfg(FILE** file, const char *file_name);
int CloseCfg(FILE* file);
int ReadCfg(FILE* file, char** buffer);
int ParseCfg(config__t *cfg, const char* data, config_overrides_t* overrides);

int GetNextAvailableFilterIndex(config__t* cfg);

#include <loader/utils/logging.h>