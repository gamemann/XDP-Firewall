#pragma once

#include "xdpfw.h"

struct config_map
{
    char *interface;
    uint16_t updateTime;
    unsigned int nostats : 1;
    struct filter filters[MAX_FILTERS];
};

void SetConfigDefaults(struct config_map *cfg);
int OpenConfig(const char *FileName);
int ReadConfig(struct config_map *cfg);