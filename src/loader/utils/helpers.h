#pragma once

#include <common/all.h>

#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

struct ip
{
    u32 ip;
    u32 cidr;
};

struct ip ParseIp(const char *ip);