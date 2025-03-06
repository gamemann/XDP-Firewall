#pragma once

#include <common/all.h>

#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/sysinfo.h>

struct ip_range
{
    u32 ip;
    u8 cidr;
} typedef ip_range_t;

extern int cont;

void print_help_menu();
void hdl_signal(int code);
ip_range_t parse_ip_range(const char* ip);
const char* get_protocol_str_by_id(int id);
void print_tool_info();
u64 get_boot_nano_time();