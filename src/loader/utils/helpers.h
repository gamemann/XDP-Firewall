#pragma once

#include <common/all.h>

#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

struct ip_range
{
    u32 ip;
    u8 cidr;
} typedef ip_range_t;

extern int cont;

void PrintHelpMenu();
void SignalHndl(int code);
ip_range_t ParseIpCidr(const char* ip);