#pragma once

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#include <time.h>

#include <common/all.h>

#include <loader/utils/config.h>

#include <xdp/libxdp.h>

#define RB_TIMEOUT 100

extern int doing_stats;

void log_msg(config__t* cfg, int req_lvl, int error, const char* msg, ...);

void poll_filters_rb(struct ring_buffer* rb);
int hdl_filters_rb_event(void* ctx, void* data, size_t sz);