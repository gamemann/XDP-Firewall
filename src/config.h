#pragma once

#include <linux/types.h>

#include "xdpfw.h"

struct config
{
    char *interface;
    __u16 updatetime;
    unsigned int nostats : 1;
    struct filter filters[MAX_FILTERS];
};

void setcfgdefaults(struct config *cfg);
int opencfg(const char *filename);
int readcfg(struct config *cfg);