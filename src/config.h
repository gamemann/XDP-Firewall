#pragma once

#include <linux/types.h>

#include "xdpfw.h"

struct config
{
    char *interface;
    __u16 updatetime;
    unsigned int nostats : 1;
    int stdout_update_time;
    struct filter filters[MAX_FILTERS];
};

void SetCfgDefaults(struct config *cfg);
int OpenCfg(const char *filename);
int ReadCfg(struct config *cfg);