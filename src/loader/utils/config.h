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
    struct filter filters[MAX_FILTERS];
};

void SetCfgDefaults(struct config *cfg);
int OpenCfg(const char *filename);
int ReadCfg(struct config *cfg);