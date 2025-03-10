#pragma once

#include <xdp/libxdp.h>

#include <common/all.h>

#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#include <time.h>

int calc_stats(int map_stats, int cpus, int per_second);