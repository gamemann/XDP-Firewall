#ifndef XDPFW_Header
#define XDPFW_Header

#include <inttypes.h>

#define MAX_PCKT_LENGTH 65535
#define MAX_FILTERS 255

struct tcpopts
{
    unsigned int enabled : 1;

    uint16_t sport;
    uint16_t dport;

    // TCP flags.
    unsigned int urg : 1;
    unsigned int ack : 1;
    unsigned int rst : 1;
    unsigned int psh : 1;
    unsigned int syn : 1;
    unsigned int fin : 1;
};

struct udpopts
{
    unsigned int enabled : 1;

    uint16_t sport;
    uint16_t dport;
};

struct icmpopts
{
    unsigned int enabled : 1;

    uint8_t code;
    uint8_t type;
};

struct filter
{
    unsigned int enabled : 1;

    uint8_t action;

    uint32_t srcIP;
    uint32_t dstIP;
    uint8_t protocol;

    uint8_t min_ttl;
    uint8_t max_ttl;

    uint16_t min_len;
    uint16_t max_len;

    uint32_t min_id;
    uint32_t max_id;

    int8_t tos;

    uint8_t payloadMatch[MAX_PCKT_LENGTH];
    uint16_t payloadLen;

    struct tcpopts tcpopts;
    struct udpopts udpopts;
    struct icmpopts icmpopts;
};

#endif