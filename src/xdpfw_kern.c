#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <inttypes.h>

#include "../libbpf/src/bpf_helpers.h"

#include <stdint.h>
#include <stdatomic.h>

#include "include/xdpfw.h"

#define DEBUG

#ifdef DEBUG

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

#endif

#define SEC(NAME) __attribute__((section(NAME), used))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

struct bpf_map_def SEC("maps") filters_map = 
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct filter),
    .max_entries = MAX_FILTERS
};

struct bpf_map_def SEC("maps") count_map = 
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint8_t),
    .max_entries = 1
};

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Check for count map.
    uint32_t key = 0;
    uint16_t *filters;

    filters = bpf_map_lookup_elem(&count_map, &key);

    // Check if the count map value is valid.
    if (filters == NULL)
    {
        return XDP_ABORTED;
    }

    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    uint8_t matched = 0;
    uint8_t action = 0;

    // Scan ethernet header.
    struct ethhdr *ethhdr = data;

    // Check if the ethernet header is valid.
    if (ethhdr + 1 > (struct ethhdr *)data_end)
    {
        return XDP_PASS;
    }

    // Let's get the filters we need.
    struct filter *filter[MAX_FILTERS];

    for (uint16_t i = 0; i < *filters; i++)
    {
        uint32_t key = i;
        
        filter[i] = bpf_map_lookup_elem(&filters_map, &key);
    }

    // Check Ethernet protocol and ensure it's IP.
    if (likely(ethhdr->h_proto == htons(ETH_P_IP)))
    {
        // Scan IP header.
        struct iphdr *iph = data + sizeof(struct ethhdr);

        // Check if the IP header is valid.
        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            return XDP_PASS;
        }

        // Let's match IP-header level filtering.
        for (uint16_t i = 0; i < *filters; i++)
        {
            // Check if enabled.
            if (filter[i]->enabled == 0)
            {
                continue;
            }

            // Source address.
            if (filter[i]->srcIP != 0 && iph->saddr != filter[i]->srcIP)
            {
                continue;
            }

            // Destination address.
            if (filter[i]->dstIP != 0 && iph->daddr != filter[i]->dstIP)
            {
                continue;
            }

            // Max TTL length.
            if (filter[i]->max_ttl > iph->ttl)
            {
                continue;
            }

            // Min TTL length.
            if (filter[i]->min_ttl < iph->ttl)
            {
                continue;
            }

            // Max packet length.
            if (filter[i]->max_len > (ntohs(iph->tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // Min packet length.
            if (filter[i]->min_len < (ntohs(iph->tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // TOS.
            if (filter[i]->tos != 0 && filter[i]->tos == iph->tos)
            {
                continue;
            }

            // Matched.
            matched = 1;
            action = filter[i]->action;

            break;
        }

        uint16_t l4headerLen = 0;

        // Check protocol.
        if (iph->protocol == IPPROTO_TCP)
        {
            // Scan TCP header.
            struct tcphdr *tcph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

            // Check TCP header.
            if (tcph + 1 > (struct tcphdr *)data_end)
            {
                return XDP_PASS;
            }

            // Set L4 Header length.
            l4headerLen = sizeof(struct tcphdr);

            // Time to loop through each filtering rule and look for TCP options.
            for (uint16_t i = 0; i < *filters; i++)
            {
                // Enabled.
                if (filter[i]->tcpopts.enabled == 0)
                {
                    continue;
                }

                // Source port.
                if (filter[i]->tcpopts.sport != 0 && htons(filter[i]->tcpopts.sport) != tcph->source)
                {
                    continue;
                }

                // Destination port.
                if (filter[i]->tcpopts.dport != 0 && htons(filter[i]->tcpopts.dport) != tcph->dest)
                {
                    continue;
                }

                // URG flag.
                if (filter[i]->tcpopts.urg != tcph->urg)
                {
                    continue;
                }

                // ACK flag.
                if (filter[i]->tcpopts.ack != tcph->ack)
                {
                    continue;
                }

                // RST flag.
                if (filter[i]->tcpopts.rst != tcph->rst)
                {
                    continue;
                }

                // PSH flag.
                if (filter[i]->tcpopts.psh != tcph->psh)
                {
                    continue;
                }

                // SYN flag.
                if (filter[i]->tcpopts.syn != tcph->syn)
                {
                    continue;
                }

                // FIN flag.
                if (filter[i]->tcpopts.fin != tcph->fin)
                {
                    continue;
                }

                matched = 1;
                action = filter[i]->action;

                break;
            }
        }
        else if (iph->protocol == IPPROTO_UDP)
        {
            // Scan UDP header.
            struct udphdr *udph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

            // Check TCP header.
            if (udph + 1 > (struct udphdr *)data_end)
            {
                return XDP_PASS;
            }

            // Set L4 Header length.
            l4headerLen = sizeof(struct udphdr);

            // Time to loop through each filtering rule and look for TCP options.
            for (uint16_t i = 0; i < *filters; i++)
            {
                // Enabled.
                if (filter[i]->udpopts.enabled == 0)
                {
                    continue;
                }

                // Source port.
                if (filter[i]->udpopts.sport != 0 && htons(filter[i]->udpopts.sport) != udph->source)
                {
                    continue;
                }

                // Destination port.
                if (filter[i]->udpopts.dport != 0 && htons(filter[i]->udpopts.dport) != udph->dest)
                {
                    continue;
                }

                matched = 1;
                action = filter[i]->action;

                break;
            }
        }
        else if (iph->protocol == IPPROTO_ICMP)
        {
            // Scan UDP header.
            struct icmphdr *icmph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

            // Check TCP header.
            if (icmph + 1 > (struct icmphdr *)data_end)
            {
                return XDP_PASS;
            }

            // Set L4 Header length.
            l4headerLen = sizeof(struct icmphdr);

            // Time to loop through each filtering rule and look for TCP options.
            for (uint16_t i = 0; i < *filters; i++)
            {
                // Enabled.
                if (filter[i]->icmpopts.enabled == 0)
                {
                    continue;
                }

                // Code.
                if (filter[i]->icmpopts.code != icmph->code)
                {
                    continue;
                }

                // Type.
                if (filter[i]->icmpopts.type != icmph->type)
                {
                    continue;
                }

                matched = 1;
                action = filter[i]->action;

                break;
            } 
        }
        
        // Finally, perform match against payload data.
        unsigned char *pcktData = (data + sizeof(struct ethhdr) + (iph->ihl * 4) + l4headerLen);

        // Check packet data.
        for (uint16_t i = 0; i < *filters; i++)
        {
            // Check if payload is set.
            if (filter[i]->payloadLen < 1)
            {
                continue;
            }

            // Now check packet data and ensure we have enough to match.
            if (pcktData + (filter[i]->payloadLen) + 1 > (unsigned char *)data_end)
            {
                continue;
            }

            uint8_t found = 1;

            for (uint16_t j = 0; i < filter[i]->payloadLen; i++)
            {
                if (*pcktData == filter[i]->payloadMatch[j])
                {
                    pcktData++;

                    continue;
                }

                found = 0;

                break;
            }

            if (found)
            {
                matched = 1;
                action = filter[i]->action;
            }

        }

    }

    if (matched && action == 0)
    {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";