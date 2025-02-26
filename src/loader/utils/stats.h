#pragma once

#include <xdp/libxdp.h>

#include <common/all.h>

#include <loader/utils/cmdline.h>
#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#include <time.h>

int CalculateStats(int stats_map, int cpus, int per_second);