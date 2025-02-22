#pragma once

#include <common/all.h>

#include <stdio.h>
#include <stdlib.h>
#include <libconfig.h>
#include <string.h>
#include <linux/types.h>

#include <arpa/inet.h>

struct config
{
    char *interface;
    u16 updatetime;
    unsigned int nostats : 1;
    int stdout_update_time;
    filter_t filters[MAX_FILTERS];
} typedef config__t; // config_t is taken by libconfig -.-

void SetCfgDefaults(config__t *cfg);
int OpenCfg(const char *filename);
int ReadCfg(config__t *cfg);