#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>

#include <common/all.h>

#include <xdp/utils/rl.h>
#include <xdp/utils/helpers.h>

#include <xdp/utils/maps.h>

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Scan ethernet header.
    struct ethhdr *eth = data;

    // Check if the ethernet header is valid.
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        return XDP_DROP;
    }

    // Check Ethernet protocol.
    if (unlikely(eth->h_proto != htons(ETH_P_IP) && eth->h_proto != htons(ETH_P_IPV6)))
    {
        return XDP_PASS;
    }

    u8 action = 0;
    __u64 blocktime = 1;

    // Initialize IP headers.
    struct iphdr *iph = NULL;
    struct ipv6hdr *iph6 = NULL;
    u128 src_ip6 = 0;

    // Set IPv4 and IPv6 common variables.
    if (eth->h_proto == htons(ETH_P_IPV6))
    {
        iph6 = (data + sizeof(struct ethhdr));

        if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
        {
            return XDP_DROP;
        }

        memcpy(&src_ip6, &iph6->saddr.in6_u.u6_addr32, sizeof(src_ip6));
    }
    else
    {
        iph = (data + sizeof(struct ethhdr));

        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            return XDP_DROP;
        }
    }
    
    // Check IP header protocols.
    if ((iph6 && iph6->nexthdr != IPPROTO_UDP && iph6->nexthdr != IPPROTO_TCP && iph6->nexthdr != IPPROTO_ICMP) && (iph && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP))
    {
        return XDP_PASS;
    }

    // Get stats map.
    u32 key = 0;
    struct stats *stats = bpf_map_lookup_elem(&stats_map, &key);

    __u64 now = bpf_ktime_get_ns();

    // Check blacklist map.
    __u64 *blocked = NULL;

    if (iph6)
    {
        blocked = bpf_map_lookup_elem(&ip6_blacklist_map, &src_ip6);
    }
    else if (iph)
    {
        blocked = bpf_map_lookup_elem(&ip_blacklist_map, &iph->saddr);
    }
    
    if (blocked != NULL && *blocked > 0)
    {
        if (now > *blocked)
        {
            // Remove element from map.
            if (iph6)
            {
                bpf_map_delete_elem(&ip6_blacklist_map, &src_ip6);
            }
            else if (iph)
            {
                bpf_map_delete_elem(&ip_blacklist_map, &iph->saddr);
            }
        }
        else
        {
#ifdef DOSTATSONBLOCKMAP
            // Increase blocked stats entry.
            if (stats)
            {
                stats->dropped++;
            }
#endif

            // They're still blocked. Drop the packet.
            return XDP_DROP;
        }
    }

    // Retrieve total packet length.
    u16 pkt_len = data_end - data;

    // Parse layer-4 headers and determine source port and protocol.
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;
    struct icmp6hdr *icmp6h = NULL;

    u16 src_port = 0;
    u8 protocol = 0;
    
    if (iph6)
    {
        protocol = iph6->nexthdr;

        switch (iph6->nexthdr)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                {
                    return XDP_DROP;
                }

                src_port = tcph->source;

                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

                // Check TCP header.
                if (unlikely(udph + 1 > (struct udphdr *)data_end))
                {
                    return XDP_DROP;
                }

                src_port = udph->source;

                break;

            case IPPROTO_ICMPV6:
                // Scan ICMPv6 header.
                icmp6h = (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));

                // Check ICMPv6 header.
                if (unlikely(icmp6h + 1 > (struct icmp6hdr *)data_end))
                {
                    return XDP_DROP;
                }

                break;
        }
    }
    else if (iph)
    {
        protocol = iph->protocol;

        switch (iph->protocol)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                {
                    return XDP_DROP;
                }

                src_port = tcph->source;

                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

                // Check TCP header.
                if (unlikely(udph + 1 > (struct udphdr *)data_end))
                {
                    return XDP_DROP;
                }

                src_port = udph->source;

                break;

            case IPPROTO_ICMP:
                // Scan ICMP header.
                icmph = (data + sizeof(struct ethhdr) + (iph->ihl * 4));

                // Check ICMP header.
                if (unlikely(icmph + 1 > (struct icmphdr *)data_end))
                {
                    return XDP_DROP;
                }

                break;
        }
    }

    // Update client stats (PPS/BPS).
    __u64 pps = 0;
    __u64 bps = 0;
    
    if (iph6)
    {
        UpdateIp6Stats(&pps, &bps, &src_ip6, src_port, protocol, pkt_len, now);
    }
    else if (iph)
    {
        UpdateIpStats(&pps, &bps, iph->saddr, src_port, protocol, pkt_len, now);
    }
    
    for (u8 i = 0; i < MAX_FILTERS; i++)
    {
        u32 key = i;

        struct filter *filter = bpf_map_lookup_elem(&filters_map, &key);

        // Check if ID is above 0 (if 0, it's an invalid rule).
        if (!filter || filter->id < 1)
        {
            break;
        }

        // Check if the rule is enabled.
        if (!filter->enabled)
        {
            continue;
        }

        // Do specific IPv6.
        if (iph6)
        {
            // Source address.
            if (filter->src_ip6[0] != 0 && (iph6->saddr.in6_u.u6_addr32[0] != filter->src_ip6[0] || iph6->saddr.in6_u.u6_addr32[1] != filter->src_ip6[1] || iph6->saddr.in6_u.u6_addr32[2] != filter->src_ip6[2] || iph6->saddr.in6_u.u6_addr32[3] != filter->src_ip6[3]))
            {
                continue;
            }

            // Destination address.
            if (filter->dst_ip6[0] != 0 && (iph6->daddr.in6_u.u6_addr32[0] != filter->dst_ip6[0] || iph6->daddr.in6_u.u6_addr32[1] != filter->dst_ip6[1] || iph6->daddr.in6_u.u6_addr32[2] != filter->dst_ip6[2] || iph6->daddr.in6_u.u6_addr32[3] != filter->dst_ip6[3]))
            {
                continue;
            }

#ifdef ALLOWSINGLEIPV4V6
            if (filter->src_ip != 0 || filter->dst_ip != 0)
            {
                continue;
            }
#endif

            // Max TTL length.
            if (filter->do_max_ttl && filter->max_ttl > iph6->hop_limit)
            {
                continue;
            }

            // Min TTL length.
            if (filter->do_min_ttl && filter->min_ttl < iph6->hop_limit)
            {
                continue;
            }

            // Max packet length.
            if (filter->do_max_len && filter->max_len > (ntohs(iph6->payload_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // Min packet length.
            if (filter->do_min_len && filter->min_len < (ntohs(iph6->payload_len) + sizeof(struct ethhdr)))
            {
                continue;
            }
        }
        else if (iph)
        {
            // Source address.
            if (filter->src_ip)
            {
                if (filter->src_cidr == 32 && iph->saddr != filter->src_ip)
                {
                    continue;
                }

                if (!IsIpInRange(iph->saddr, filter->src_ip, filter->src_cidr))
                {
                    continue;
                }
            }

            // Destination address.
            if (filter->dst_ip)
            {
                if (filter->dst_cidr == 32 && iph->daddr != filter->dst_ip)
                {
                    continue;
                }
                
                if (!IsIpInRange(iph->daddr, filter->dst_ip, filter->dst_cidr))
                {
                    continue;
                }
            }

#ifdef ALLOWSINGLEIPV4V6
            if ((filter->src_ip6[0] != 0 || filter->src_ip6[1] != 0 || filter->src_ip6[2] != 0 || filter->src_ip6[3] != 0) || (filter->dst_ip6[0] != 0 || filter->dst_ip6[1] != 0 || filter->dst_ip6[2] != 0 || filter->dst_ip6[3] != 0))
            {
                continue;
            }
#endif

            // TOS.
            if (filter->do_tos && filter->tos != iph->tos)
            {
                continue;
            }

            // Max TTL length.
            if (filter->do_max_ttl && filter->max_ttl < iph->ttl)
            {
                continue;
            }

            // Min TTL length.
            if (filter->do_min_ttl && filter->min_ttl > iph->ttl)
            {
                continue;
            }

            // Max packet length.
            if (filter->do_max_len && filter->max_len < (ntohs(iph->tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }

            // Min packet length.
            if (filter->do_min_len && filter->min_len > (ntohs(iph->tot_len) + sizeof(struct ethhdr)))
            {
                continue;
            }
        }

        // PPS.
        if (filter->do_pps &&  pps < filter->pps)
        {
            continue;
        }

        // BPS.
        if (filter->do_bps && bps < filter->bps)
        {
            continue;
        }
        
        // Do TCP options.
        if (filter->tcpopts.enabled)
        {
            if (!tcph)
            {
                continue;
            }

            // Source port.
            if (filter->tcpopts.do_sport && htons(filter->tcpopts.sport) != tcph->source)
            {
                continue;
            }

            // Destination port.
            if (filter->tcpopts.do_dport && htons(filter->tcpopts.dport) != tcph->dest)
            {
                continue;
            }

            // URG flag.
            if (filter->tcpopts.do_urg && filter->tcpopts.urg != tcph->urg)
            {
                continue;
            }

            // ACK flag.
            if (filter->tcpopts.do_ack && filter->tcpopts.ack != tcph->ack)
            {
                continue;
            }

            // RST flag.
            if (filter->tcpopts.do_rst && filter->tcpopts.rst != tcph->rst)
            {
                continue;
            }

            // PSH flag.
            if (filter->tcpopts.do_psh && filter->tcpopts.psh != tcph->psh)
            {
                continue;
            }

            // SYN flag.
            if (filter->tcpopts.do_syn && filter->tcpopts.syn != tcph->syn)
            {
                continue;
            }

            // FIN flag.
            if (filter->tcpopts.do_fin && filter->tcpopts.fin != tcph->fin)
            {
                continue;
            }

            // ECE flag.
            if (filter->tcpopts.do_ece && filter->tcpopts.ece != tcph->ece)
            {
                continue;
            }

            // CWR flag.
            if (filter->tcpopts.do_cwr && filter->tcpopts.cwr != tcph->cwr)
            {
                continue;
            }
        }
        else if (filter->udpopts.enabled)
        {
            if (!udph)
            {
                continue;
            }

            // Source port.
            if (filter->udpopts.do_sport && htons(filter->udpopts.sport) != udph->source)
            {
                continue;
            }

            // Destination port.
            if (filter->udpopts.do_dport && htons(filter->udpopts.dport) != udph->dest)
            {

                continue;
            }
        }
        else if (filter->icmpopts.enabled)
        {
            if (icmph)
            {
                // Code.
                if (filter->icmpopts.do_code && filter->icmpopts.code != icmph->code)
                {
                    continue;
                }

                // Type.
                if (filter->icmpopts.do_type && filter->icmpopts.type != icmph->type)
                {
                    continue;
                }  
            }
            else if (icmp6h)
            {
                // Code.
                if (filter->icmpopts.do_code && filter->icmpopts.code != icmp6h->icmp6_code)
                {
                    continue;
                }

                // Type.
                if (filter->icmpopts.do_type && filter->icmpopts.type != icmp6h->icmp6_type)
                {
                    continue;
                }
            }
            else
            {
                continue;
            }
        }
        
        // Matched.
        action = filter->action;
        blocktime = filter->blocktime;

        goto matched;
    }

    if (stats)
    {
        stats->passed++;
    }
            
    return XDP_PASS;

    matched:
    if (action == 0)
    {
        // Before dropping, update the blacklist map.
        if (blocktime > 0)
        {
            __u64 newTime = now + (blocktime * NANO_TO_SEC);
            
            if (iph6)
            {
                bpf_map_update_elem(&ip6_blacklist_map, &src_ip6, &newTime, BPF_ANY);
            }
            else if (iph)
            {
                bpf_map_update_elem(&ip_blacklist_map, &iph->saddr, &newTime, BPF_ANY);
            }
        }

        if (stats)
        {
            stats->dropped++;
        }

        return XDP_DROP;
    }
    else
    {
        if (stats)
        {
            stats->allowed++;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);