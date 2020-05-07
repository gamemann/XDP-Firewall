#ifndef XDPFW_Header
#define XDPFW_Header

#include <inttypes.h>

#define MAX_PCKT_LENGTH 65535
#define MAX_FILTERS 50
#define MAX_CPUS 128
#define LRU_MAP_SIZE 16384

struct tcpopts
{
    unsigned int enabled : 1;

    unsigned int do_sport : 1;
    uint16_t sport;

    unsigned int do_dport : 1;
    uint16_t dport;

    // TCP flags.
    unsigned int do_urg : 1;
    unsigned int urg : 1;

    unsigned int do_ack : 1;
    unsigned int ack : 1;

    unsigned int do_rst : 1;
    unsigned int rst : 1;

    unsigned int do_psh : 1;
    unsigned int psh : 1;

    unsigned int do_syn : 1;
    unsigned int syn : 1;

    unsigned int do_fin : 1;
    unsigned int fin : 1;
};

struct udpopts
{
    unsigned int enabled : 1;

    unsigned int do_sport : 1;
    uint16_t sport;

    unsigned int do_dport : 1;
    uint16_t dport;
};

struct icmpopts
{
    unsigned int enabled : 1;

    unsigned int do_code : 1;
    uint8_t code;

    unsigned int do_type : 1;
    uint8_t type;
};

struct filter
{
    uint8_t id;

    unsigned int enabled : 1;

    uint8_t action;

    uint32_t srcIP;
    uint32_t dstIP;

    unsigned int do_min_ttl : 1;
    uint8_t min_ttl;

    unsigned int do_max_ttl : 1;
    uint8_t max_ttl;

    unsigned int do_min_len : 1;
    uint16_t min_len;

    unsigned int do_max_len : 1;
    uint16_t max_len;

    unsigned int do_tos : 1;
    int8_t tos;

    unsigned int do_pps : 1;
    uint64_t pps;

    unsigned int do_bps : 1;
    uint64_t bps;

    uint8_t payloadMatch[MAX_PCKT_LENGTH];
    uint16_t payloadLen;

    struct tcpopts tcpopts;
    struct udpopts udpopts;
    struct icmpopts icmpopts;
};

struct xdpfw_stats
{
    uint64_t allowed;
    uint64_t blocked;
};

struct xdpfw_ip_stats
{
    uint64_t pps;
    uint64_t bps;
    uint64_t tracking;
};

#endif