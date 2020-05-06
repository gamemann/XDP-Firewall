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

//#define DEBUG

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

struct bpf_map_def SEC("maps") stats_map =
{
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct xdpfw_stats),
    .max_entries = 1
};

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{    
    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Scan ethernet header.
    struct ethhdr *ethhdr = data;

    // Check if the ethernet header is valid.
    if (ethhdr + 1 > (struct ethhdr *)data_end)
    {
        return XDP_DROP;
    }

    // Let's get the filters we need.
    struct filter *filter[MAX_FILTERS];

    for (uint8_t i = 0; i < MAX_FILTERS; i++)
    {
        uint32_t key = i;
        
        filter[i] = bpf_map_lookup_elem(&filters_map, &key);
    }

    uint8_t matched = 0;
    uint8_t action = 0;

    // Check Ethernet protocol and ensure it's IP.
    if (likely(ethhdr->h_proto == htons(ETH_P_IP)))
    {
        // Scan IP header.
        struct iphdr *iph = data + sizeof(struct ethhdr);

        // Check if the IP header is valid.
        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            return XDP_DROP;
        }
        
        // Check IP header protocols.
        if (unlikely(iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP))
        {
            return XDP_PASS;
        }

        struct tcphdr *tcph;
        struct udphdr *udph;
        struct icmphdr *icmph;
        
        uint16_t l4headerLen = 0;

        // Check protocol.
        if (iph->protocol == IPPROTO_TCP)
        {
            // Scan TCP header.
            tcph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

            // Check TCP header.
            if (tcph + 1 > (struct tcphdr *)data_end)
            {
                return XDP_PASS;
            }

            // Set L4 Header length.
            l4headerLen = sizeof(struct tcphdr);
        }
        else if (iph->protocol == IPPROTO_UDP)
        {
            // Scan UDP header.
            udph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

            // Check TCP header.
            if (udph + 1 > (struct udphdr *)data_end)
            {
                return XDP_PASS;
            }

            // Set L4 Header length.
            l4headerLen = sizeof(struct udphdr);
        }
        else if (iph->protocol == IPPROTO_ICMP)
        {
            // Scan UDP header.
            icmph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

            // Check TCP header.
            if (icmph + 1 > (struct icmphdr *)data_end)
            {
                return XDP_PASS;
            }

            // Set L4 Header length.
            l4headerLen = sizeof(struct icmphdr);
        }
        
        for (uint8_t i = 0; i < MAX_FILTERS; i++)
        {
            // Check if ID is above 0 (if 0, it's an invalid rule).
            if (!filter[i] || filter[i]->id < 1)
            {
                break;
            }

            // Check if the rule is enabled.
            if (!filter[i]->enabled)
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
            if (filter[i]->do_max_ttl && filter[i]->max_ttl > iph->ttl)
            {
                continue;
            }

            // Min TTL length.
            if (filter[i]->do_min_ttl && filter[i]->min_ttl < iph->ttl)
            {
                continue;
            }

            // Max packet length.
            if (filter[i]->do_max_len && filter[i]->max_len > (ntohs(iph->tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // Min packet length.
            if (filter[i]->do_min_len && filter[i]->min_len < (ntohs(iph->tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // TOS.
            if (filter[i]->do_tos && filter[i]->tos != iph->tos)
            {
                continue;
            }

            // Payload match.
            /*
            if (filter[i]->payloadLen > 0)
            {
                uint8_t found = 1;
                uint16_t len = filter[i]->payloadLen;

                // Initialize packet data.
                uint8_t *pcktData = (data + sizeof(struct ethhdr) + (iph->ihl * 4) + l4headerLen);

                if (pcktData + len > (uint8_t *)data_end)
                {
                    continue;
                }

                for (uint16_t j = 0; j < filter[i]->payloadLen; j++)
                {
                    if ((*pcktData++) == filter[i]->payloadMatch[j])
                    {
                        continue;
                    }

                    found = 0;

                    break;
                }

                if (!found)
                {
                    continue;
                }
            }
            */

            // Check layer 4 filters.
            if (iph->protocol == IPPROTO_TCP && !filter[i]->tcpopts.enabled)
            {
                continue;
            }
            else if (iph->protocol == IPPROTO_UDP && !filter[i]->udpopts.enabled)
            {
                continue;
            }
            else if (iph->protocol == IPPROTO_ICMP && !filter[i]->icmpopts.enabled)
            {
                continue;
            }

            // Do TCP options.
            if (iph->protocol == IPPROTO_TCP && filter[i]->tcpopts.enabled)
            {
                // Source port.
                if (filter[i]->tcpopts.do_sport && htons(filter[i]->tcpopts.sport) != tcph->source)
                {
                    continue;
                }

                // Destination port.
                if (filter[i]->tcpopts.do_dport && htons(filter[i]->tcpopts.dport) != tcph->dest)
                {
                    continue;
                }

                // URG flag.
                if (filter[i]->tcpopts.do_urg && filter[i]->tcpopts.urg != tcph->urg)
                {
                    continue;
                }

                // ACK flag.
                if (filter[i]->tcpopts.do_ack && filter[i]->tcpopts.ack != tcph->ack)
                {
                    continue;
                }

                // RST flag.
                if (filter[i]->tcpopts.do_rst && filter[i]->tcpopts.rst != tcph->rst)
                {
                    continue;
                }

                // PSH flag.
                if (filter[i]->tcpopts.do_psh && filter[i]->tcpopts.psh != tcph->psh)
                {
                    continue;
                }

                // SYN flag.
                if (filter[i]->tcpopts.do_syn && filter[i]->tcpopts.syn != tcph->syn)
                {
                    continue;
                }

                // FIN flag.
                if (filter[i]->tcpopts.do_fin && filter[i]->tcpopts.fin != tcph->fin)
                {
                    continue;
                }
            }
            else if (iph->protocol == IPPROTO_UDP && filter[i]->udpopts.enabled)
            {
                // Source port.
                if (filter[i]->udpopts.do_sport && htons(filter[i]->udpopts.sport) != udph->source)
                {
                    continue;
                }

                // Destination port.
                if (filter[i]->udpopts.do_dport && htons(filter[i]->udpopts.dport) != udph->dest)
                {
                    continue;
                }
            }
            else if (iph->protocol == IPPROTO_ICMP && filter[i]->icmpopts.enabled)
            {
                // Code.
                if (filter[i]->icmpopts.do_code && filter[i]->icmpopts.code != icmph->code)
                {
                    continue;
                }

                // Type.
                if (filter[i]->icmpopts.do_type && filter[i]->icmpopts.type != icmph->type)
                {
                    continue;
                }
            }

            // Matched.
            #ifdef DEBUG
                bpf_printk("Matched rule ID #%" PRIu8 "\n", filter[i]->id);
            #endif

            matched = 1;
            action = filter[i]->action;

            break;
        }

        if (matched)
        {
            // Get stats map.
            uint32_t key = 0;
            struct xdpfw_stats *stats;

            stats = bpf_map_lookup_elem(&stats_map, &key);

            if (stats)
            {
                // Update stats map.
                if (action == 0)
                {
                    stats->blocked++;
                }
                else
                {
                    stats->allowed++;
                }

                key = 0;

                bpf_map_update_elem(&stats_map, &key, stats, BPF_ANY);
            }

            #ifdef DEBUG
                bpf_printk("Matched with protocol %" PRIu8 " and sAddr %" PRIu32 "\n", iph->protocol, iph->saddr);
            #endif
        }
    }

    if (matched && action == 0)
    {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";