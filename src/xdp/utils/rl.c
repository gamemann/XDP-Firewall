#include <xdp/utils/rl.h>

/**
 * Updates IPv4 client stats.
 * 
 * @param pps A pointer to the PPS integer.
 * @param bps A pointer to the BPS integer.
 * @param ip The client's source IP.
 * @param port The client's source port.
 * @param protocol The client's protocol.
 * @param pkt_len The total packet length.
 * @param now The current time since boot in nanoseconds.alignas
 * 
 * @return void
*/
static __always_inline void UpdateIpStats(__u64 *pps, __u64 *bps, u32 ip, u16 port, u8 protocol, u16 pkt_len, __u64 now)
{
#ifdef USE_FLOW_RL
    struct flow key = {0};
    key.ip = ip;
    key.port = port;
    key.protocol = protocol;

    struct ip_stats *ip_stats = bpf_map_lookup_elem(&ip_stats_map, &key);
#else
    struct ip_stats *ip_stats = bpf_map_lookup_elem(&ip_stats_map, &ip);
#endif

    if (ip_stats)
    {
        // Check for next update.
        if (now > ip_stats->next_update)
        {
            ip_stats->pps = 1;
            ip_stats->bps = pkt_len;
            ip_stats->next_update = now + NANO_TO_SEC;
        }
        else
        {
            // Increment PPS and BPS using built-in functions.
            __sync_fetch_and_add(&ip_stats->pps, 1);
            __sync_fetch_and_add(&ip_stats->bps, pkt_len);
        }

        *pps = ip_stats->pps;
        *bps = ip_stats->bps;
    }
    else
    {
        // Create new entry.
        struct ip_stats new = {0};

        new.pps = 1;
        new.bps = pkt_len;
        new.next_update = now + NANO_TO_SEC;

        *pps = new.pps;
        *bps = new.bps;

#ifdef USE_FLOW_RL
        bpf_map_update_elem(&ip_stats_map, &key, &new, BPF_ANY);
#else
        bpf_map_update_elem(&ip_stats_map, &ip, &new, BPF_ANY);
#endif
    }
}

/**
 * Updates IPv6 client stats.
 * 
 * @param pps A pointer to the PPS integer.
 * @param bps A pointer to the BPS integer.
 * @param ip The client's source IP.
 * @param port The client's source port.
 * @param protocol The client's protocol.
 * @param pkt_len The total packet length.
 * @param now The current time since boot in nanoseconds.alignas
 * 
 * @return void
*/
static __always_inline void UpdateIp6Stats(__u64 *pps, __u64 *bps, u128 *ip, u16 port, u8 protocol, u16 pkt_len, __u64 now)
{
#ifdef USE_FLOW_RL
    struct flow6 key = {0};
    key.ip = *ip;
    key.port = port;
    key.protocol = protocol;

    struct ip_stats *ip_stats = bpf_map_lookup_elem(&ip_stats_map, &key);
#else
    struct ip_stats *ip_stats = bpf_map_lookup_elem(&ip_stats_map, ip);
#endif

    if (ip_stats)
    {
        // Check for next update.
        if (now > ip_stats->next_update)
        {
            ip_stats->pps = 1;
            ip_stats->bps = pkt_len;
            ip_stats->next_update = now + NANO_TO_SEC;
        }
        else
        {
            // Increment PPS and BPS using built-in functions.
            __sync_fetch_and_add(&ip_stats->pps, 1);
            __sync_fetch_and_add(&ip_stats->bps, pkt_len);
        }

        *pps = ip_stats->pps;
        *bps = ip_stats->bps;
    }
    else
    {
        // Create new entry.
        struct ip_stats new = {0};

        new.pps = 1;
        new.bps = pkt_len;
        new.next_update = now + NANO_TO_SEC;

        *pps = new.pps;
        *bps = new.bps;

#ifdef USE_FLOW_RL
        bpf_map_update_elem(&ip_stats_map, &key, &new, BPF_ANY);
#else
        bpf_map_update_elem(&ip_stats_map, ip, &new, BPF_ANY);
#endif
    }
}