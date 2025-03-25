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
#include <xdp/utils/logging.h>
#include <xdp/utils/stats.h>
#include <xdp/utils/helpers.h>

#include <xdp/utils/maps.h>

struct 
{
    __uint(priority, 10);
    __uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_prog_main);

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Retrieve stats map value.
    u32 key = 0;
    stats_t* stats = bpf_map_lookup_elem(&map_stats, &key);

    // Scan ethernet header.
    struct ethhdr *eth = data;

    // Check if the ethernet header is valid.
    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }

    // Check Ethernet protocol.
#ifdef ENABLE_IPV6
    if (unlikely(eth->h_proto != htons(ETH_P_IP) && eth->h_proto != htons(ETH_P_IPV6)))
#else
    if (unlikely(eth->h_proto != htons(ETH_P_IP)))
#endif
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);
        
        return XDP_PASS;
    }

    // Initialize IP headers.
    struct iphdr *iph = NULL;
    struct ipv6hdr *iph6 = NULL;
    u128 src_ip6 = 0;

    // Set IPv4 and IPv6 common variables.
    if (eth->h_proto == htons(ETH_P_IP))
    {
        iph = data + sizeof(struct ethhdr);

        if (unlikely(iph + 1 > (struct iphdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }
    }
#ifdef ENABLE_IPV6
    else
    {
        iph6 = data + sizeof(struct ethhdr);

        if (unlikely(iph6 + 1 > (struct ipv6hdr *)data_end))
        {
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);

            return XDP_DROP;
        }

        memcpy(&src_ip6, iph6->saddr.in6_u.u6_addr32, sizeof(src_ip6));
    }
#endif
    
    // We only want to process TCP, UDP, and ICMP packets.
    if ((iph6 && iph6->nexthdr != IPPROTO_UDP && iph6->nexthdr != IPPROTO_TCP && iph6->nexthdr != IPPROTO_ICMP) && (iph && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_ICMP))
    {
        inc_pkt_stats(stats, STATS_TYPE_PASSED);

        return XDP_PASS;
    }

    // Retrieve nanoseconds since system boot as timestamp.
    u64 now = bpf_ktime_get_ns();

    // Check block map.
    u64 *blocked = NULL;

    if (iph)
    {
        blocked = bpf_map_lookup_elem(&map_block, &iph->saddr);
    }
#ifdef ENABLE_IPV6
    else
    {
        blocked = bpf_map_lookup_elem(&map_block6, &src_ip6);
    }
#endif
    
    if (blocked != NULL)
    {
        if (*blocked > 0 && now > *blocked)
        {
            // Remove element from map.
            if (iph)
            {
                bpf_map_delete_elem(&map_block, &iph->saddr);
            }
#ifdef ENABLE_IPV6
            else
            {
                bpf_map_delete_elem(&map_block6, &src_ip6);
            }
#endif
        }
        else
        {
#ifdef DO_STATS_ON_BLOCK_MAP
            // Increase blocked stats entry.
            inc_pkt_stats(stats, STATS_TYPE_DROPPED);
#endif

            // They're still blocked. Drop the packet.
            return XDP_DROP;
        }
    }

#ifdef ENABLE_IP_RANGE_DROP
    if (iph && check_ip_range_drop(iph->saddr))
    {
#ifdef DO_STATS_ON_IP_RANGE_DROP_MAP
        inc_pkt_stats(stats, STATS_TYPE_DROPPED);
#endif

        return XDP_DROP;
    }
#endif

#ifdef ENABLE_FILTERS
    // Retrieve total packet length.
    u16 pkt_len = data_end - data;

    // Parse layer-4 headers and determine source port and protocol.
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;
    struct icmp6hdr *icmp6h = NULL;

    u16 src_port = 0;

#ifdef ENABLE_FILTER_LOGGING
    u16 dst_port = 0;
#endif

    u8 protocol = 0;
    
    if (iph)
    {
        protocol = iph->protocol;

        switch (iph->protocol)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = tcph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = tcph->dest;
#endif

                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                // Check UDP header.
                if (unlikely(udph + 1 > (struct udphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = udph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = udph->dest;
#endif

                break;

            case IPPROTO_ICMP:
                // Scan ICMP header.
                icmph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

                // Check ICMP header.
                if (unlikely(icmph + 1 > (struct icmphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                break;
        }
    }
#ifdef ENABLE_IPV6
    else if (iph6)
    {
        protocol = iph6->nexthdr;

        switch (iph6->nexthdr)
        {
            case IPPROTO_TCP:
                // Scan TCP header.
                tcph = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // Check TCP header.
                if (unlikely(tcph + 1 > (struct tcphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = tcph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = tcph->dest;
#endif

                break;

            case IPPROTO_UDP:
                // Scan UDP header.
                udph = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // Check TCP header.
                if (unlikely(udph + 1 > (struct udphdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                src_port = udph->source;

#ifdef ENABLE_FILTER_LOGGING
                dst_port = udph->dest;
#endif

                break;

            case IPPROTO_ICMPV6:
                // Scan ICMPv6 header.
                icmp6h = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

                // Check ICMPv6 header.
                if (unlikely(icmp6h + 1 > (struct icmp6hdr *)data_end))
                {
                    inc_pkt_stats(stats, STATS_TYPE_DROPPED);

                    return XDP_DROP;
                }

                break;
        }
    }
#endif

#ifdef ENABLE_FILTERS
    // Update client stats (PPS/BPS).
    u64 ip_pps = 0;
    u64 ip_bps = 0;

    u64 flow_pps = 0;
    u64 flow_bps = 0;

#if defined(ENABLE_RL_IP) || defined(ENABLE_RL_FLOW)
    if (iph)
    {
#ifdef ENABLE_RL_IP
        update_ip_stats(&ip_pps, &ip_bps, iph->saddr, pkt_len, now);
#endif

#ifdef ENABLE_RL_FLOW
        update_flow_stats(&flow_pps, &flow_bps, iph->saddr, src_port, protocol, pkt_len, now);
#endif
    }
#ifdef ENABLE_IPV6
    else if (iph6)
    {
#ifdef ENABLE_RL_IP
        update_ip6_stats(&ip_pps, &ip_bps, &src_ip6, pkt_len, now);
#endif

#ifdef ENABLE_RL_FLOW
        update_flow6_stats(&flow_pps, &flow_bps, &src_ip6, src_port, protocol, pkt_len, now);
#endif
    }
#endif
#endif
#endif

    int action = 0;
    u64 block_time = 1;

#pragma unroll 30
    for (int i = 0; i < MAX_FILTERS; i++)
    {
        u32 key = i;

        filter_t *filter = bpf_map_lookup_elem(&map_filters, &key);

        if (!filter || !filter->set)
        {
            break;
        }

#ifdef ENABLE_RL_IP
        // Check source IP rate limits.
        if (filter->do_ip_pps && ip_pps < filter->ip_pps)
        {
            continue;
        }

        if (filter->do_ip_bps && ip_bps < filter->ip_bps)
        {
            continue;
        }
#endif

#ifdef ENABLE_RL_FLOW
        // Check source flow rate limits.
        if (filter->do_flow_pps && flow_pps < filter->flow_pps)
        {
            continue;
        }

        if (filter->do_flow_bps && flow_bps < filter->flow_bps)
        {
            continue;
        }
#endif

        // Match IP settings.
        if (iph)
        {
            // Source address.
            if (filter->ip.src_ip)
            {
                if (filter->ip.src_cidr == 32 && iph->saddr != filter->ip.src_ip)
                {
                    continue;
                }

                if (!is_ip_in_range(iph->saddr, filter->ip.src_ip, filter->ip.src_cidr))
                {
                    continue;
                }
            }

            // Destination address.
            if (filter->ip.dst_ip)
            {
                if (filter->ip.dst_cidr == 32 && iph->daddr != filter->ip.dst_ip)
                {
                    continue;
                }
                
                if (!is_ip_in_range(iph->daddr, filter->ip.dst_ip, filter->ip.dst_cidr))
                {
                    continue;
                }
            }

#if defined(ENABLE_IPV6) && defined(ALLOW_SINGLE_IP_V4_V6)
            if ((filter->ip.src_ip6[0] != 0 || filter->ip.src_ip6[1] != 0 || filter->ip.src_ip6[2] != 0 || filter->ip.src_ip6[3] != 0) || (filter->ip.dst_ip6[0] != 0 || filter->ip.dst_ip6[1] != 0 || filter->ip.dst_ip6[2] != 0 || filter->ip.dst_ip6[3] != 0))
            {
                continue;
            }
#endif

            // TOS.
            if (filter->ip.do_tos && filter->ip.tos != iph->tos)
            {
                continue;
            }

            // Max TTL.
            if (filter->ip.do_max_ttl && filter->ip.max_ttl < iph->ttl)
            {
                continue;
            }

            // Min TTL.
            if (filter->ip.do_min_ttl && filter->ip.min_ttl > iph->ttl)
            {
                continue;
            }

            // Max packet length.
            if (filter->ip.do_max_len && filter->ip.max_len < pkt_len)
            {
                continue;
            }

            // Min packet length.
            if (filter->ip.do_min_len && filter->ip.min_len > pkt_len)
            {
                continue;
            }
        }
#ifdef ENABLE_IPV6
        else if (iph6)
        {
            // Source address.
            if (filter->ip.src_ip6[0] != 0 && (iph6->saddr.in6_u.u6_addr32[0] != filter->ip.src_ip6[0] || iph6->saddr.in6_u.u6_addr32[1] != filter->ip.src_ip6[1] || iph6->saddr.in6_u.u6_addr32[2] != filter->ip.src_ip6[2] || iph6->saddr.in6_u.u6_addr32[3] != filter->ip.src_ip6[3]))
            {
                continue;
            }

            // Destination address.
            if (filter->ip.dst_ip6[0] != 0 && (iph6->daddr.in6_u.u6_addr32[0] != filter->ip.dst_ip6[0] || iph6->daddr.in6_u.u6_addr32[1] != filter->ip.dst_ip6[1] || iph6->daddr.in6_u.u6_addr32[2] != filter->ip.dst_ip6[2] || iph6->daddr.in6_u.u6_addr32[3] != filter->ip.dst_ip6[3]))
            {
                continue;
            }

#ifdef ALLOW_SINGLE_IP_V4_V6
            if (filter->ip.src_ip != 0 || filter->ip.dst_ip != 0)
            {
                continue;
            }
#endif

            // Max TTL length.
            if (filter->ip.do_max_ttl && filter->ip.max_ttl < iph6->hop_limit)
            {
                continue;
            }

            // Min TTL length.
            if (filter->ip.do_min_ttl && filter->ip.min_ttl > iph6->hop_limit)
            {
                continue;
            }

            // Max packet length.
            if (filter->ip.do_max_len && filter->ip.max_len < pkt_len)
            {
                continue;
            }

            // Min packet length.
            if (filter->ip.do_min_len && filter->ip.min_len > pkt_len)
            {
                continue;
            }
        }
#endif

        // Check TCP matches.
        if (filter->tcp.enabled)
        {
            if (!tcph)
            {
                continue;
            }

            // Source port checks.
            if (filter->tcp.do_sport_min && tcph->source < filter->tcp.sport_min)
            {
                continue;
            }

            if (filter->tcp.do_sport_max && tcph->source > filter->tcp.sport_max)
            {
                continue;
            }

            // Destination port checks.
            if (filter->tcp.do_dport_min && tcph->dest < filter->tcp.dport_min)
            {
                continue;
            }

            if (filter->tcp.do_dport_max && tcph->dest > filter->tcp.dport_max)
            {
                continue;
            }

            // URG flag.
            if (filter->tcp.do_urg && filter->tcp.urg != tcph->urg)
            {
                continue;
            }

            // ACK flag.
            if (filter->tcp.do_ack && filter->tcp.ack != tcph->ack)
            {
                continue;
            }

            // RST flag.
            if (filter->tcp.do_rst && filter->tcp.rst != tcph->rst)
            {
                continue;
            }

            // PSH flag.
            if (filter->tcp.do_psh && filter->tcp.psh != tcph->psh)
            {
                continue;
            }

            // SYN flag.
            if (filter->tcp.do_syn && filter->tcp.syn != tcph->syn)
            {
                continue;
            }

            // FIN flag.
            if (filter->tcp.do_fin && filter->tcp.fin != tcph->fin)
            {
                continue;
            }

            // ECE flag.
            if (filter->tcp.do_ece && filter->tcp.ece != tcph->ece)
            {
                continue;
            }

            // CWR flag.
            if (filter->tcp.do_cwr && filter->tcp.cwr != tcph->cwr)
            {
                continue;
            }
        }
        // Check UDP matches.
        else if (filter->udp.enabled)
        {
            if (!udph)
            {
                continue;
            }

            // Source port checks.
            if (filter->udp.do_sport_min && udph->source < filter->udp.sport_min)
            {
                continue;
            }

            if (filter->udp.do_sport_max && udph->source > filter->udp.sport_max)
            {
                continue;
            }

            // Destination port checks.
            if (filter->udp.do_dport_min && udph->dest < filter->udp.dport_min)
            {
                continue;
            }

            if (filter->udp.do_dport_max && udph->dest > filter->udp.dport_max)
            {
                continue;
            }
        }
        else if (filter->icmp.enabled)
        {
            if (icmph)
            {
                // Code.
                if (filter->icmp.do_code && filter->icmp.code != icmph->code)
                {
                    continue;
                }

                // Type.
                if (filter->icmp.do_type && filter->icmp.type != icmph->type)
                {
                    continue;
                }  
            }
#ifdef ENABLE_IPV6
            else if (icmp6h)
            {
                // Code.
                if (filter->icmp.do_code && filter->icmp.code != icmp6h->icmp6_code)
                {
                    continue;
                }

                // Type.
                if (filter->icmp.do_type && filter->icmp.type != icmp6h->icmp6_type)
                {
                    continue;
                }
            }
#endif
        }

#ifdef ENABLE_FILTER_LOGGING
        if (filter->log > 0)
        {
            log_filter_msg(iph, iph6, src_port, dst_port, protocol, now, ip_pps, ip_bps, flow_pps, flow_bps, pkt_len, i);
        }
#endif
        
        // Matched.
        action = filter->action;
        block_time = filter->block_time;

        goto matched;
    }
#endif

    inc_pkt_stats(stats, STATS_TYPE_PASSED);
            
    return XDP_PASS;

#ifdef ENABLE_FILTERS
matched:
    if (action == 0)
    {
        // Before dropping, update the block map.
        if (block_time > 0)
        {
            u64 new_time = now + (block_time * NANO_TO_SEC);
            
            if (iph)
            {
                bpf_map_update_elem(&map_block, &iph->saddr, &new_time, BPF_ANY);
            }
#ifdef ENABLE_IPV6
            else
            {
                bpf_map_update_elem(&map_block6, &src_ip6, &new_time, BPF_ANY);
            }
#endif      
        }

        inc_pkt_stats(stats, STATS_TYPE_DROPPED);

        return XDP_DROP;
    }
    else
    {
        inc_pkt_stats(stats, STATS_TYPE_ALLOWED);
    }

    return XDP_PASS;
#endif
}

char _license[] SEC("license") = "GPL";

__uint(xsk_prog_version, XDP_DISPATCHER_VERSION) SEC(XDP_METADATA_SECTION);