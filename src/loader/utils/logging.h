#pragma once

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <time.h>

#include <common/all.h>

#include <loader/utils/config.h>

#include <xdp/libxdp.h>

#define RB_TIMEOUT 100

void LogMsg(config__t* cfg, int req_lvl, int error, const char* msg, ...);
int HandleRbEvent(void* ctx, void* data, size_t sz);