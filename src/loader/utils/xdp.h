#pragma once

#include <xdp/libxdp.h>

#include  <common/all.h>

#include <loader/utils/cmdline.h>
#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#define XDP_OBJ_PATH "/etc/xdpfw/xdp_prog.o"

int FindMapFd(struct xdp_program *prog, const char *map_name);
void SetLibBPFLogMode(int silent);
struct xdp_program *LoadBpfObj(const char *file_name);
int AttachXdp(struct xdp_program *prog, char** mode, int ifidx, u8 detach, cmdline_t *cmd);
void UpdateFilters(int map_filters, config__t *cfg);