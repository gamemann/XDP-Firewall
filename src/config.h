#pragma once

#include "xdpfw.h"

struct config_map
{
    char *interface;
    uint16_t updateTime;
    unsigned int nostats : 1;
    struct filter filters[MAX_FILTERS];
};

void setcfgdefaults(struct config_map *cfg);
int opencfg(const char *FileName);
int readcfg(struct config_map *cfg);