#include <xdp/utils/rl.h>

#ifdef ENABLE_FILTERS

#ifdef ENABLE_RL_IP
/**
 * Updates source IPv4 address stats.
 * 
 * @param pps A pointer to the PPS integer.
 * @param bps A pointer to the BPS integer.
 * @param ip The client's source IP.
 * @param pkt_len The total packet length.
 * @param now The current time since boot in nanoseconds.alignas
 * 
 * @return always 0
 */
static __always_inline int update_ip_stats(u64 *pps, u64 *bps, u32 ip, u16 pkt_len, u64 now)
{
    cl_stats_t* stats = bpf_map_lookup_elem(&map_ip_stats, &ip);

    if (stats)
    {
        // Check for next update.
        if (now > stats->next_update)
        {
            stats->pps = 1;
            stats->bps = pkt_len;
            stats->next_update = now + NANO_TO_SEC;
        }
        else
        {
            // Increment PPS and BPS using built-in functions.
            __sync_fetch_and_add(&stats->pps, 1);
            __sync_fetch_and_add(&stats->bps, pkt_len);
        }

        *pps = stats->pps;
        *bps = stats->bps;
    }
    else
    {
        // Create new entry.
        cl_stats_t new = {0};

        new.pps = 1;
        new.bps = pkt_len;
        new.next_update = now + NANO_TO_SEC;

        *pps = new.pps;
        *bps = new.bps;

        bpf_map_update_elem(&map_ip_stats, &ip, &new, BPF_ANY);
    }

    return 0;
}

#ifdef ENABLE_IPV6
/**
 * Updates source IPv6 address stats.
 * 
 * @param pps A pointer to the PPS integer.
 * @param bps A pointer to the BPS integer.
 * @param ip The client's source IP.
 * @param pkt_len The total packet length.
 * @param now The current time since boot in nanoseconds.alignas
 * 
 * @return always 0
 */
static __always_inline int update_ip6_stats(u64 *pps, u64 *bps, u128 *ip, u16 pkt_len, u64 now)
{
    cl_stats_t* stats = bpf_map_lookup_elem(&map_ip6_stats, ip);

    if (stats)
    {
        // Check for next update.
        if (now > stats->next_update)
        {
            stats->pps = 1;
            stats->bps = pkt_len;
            stats->next_update = now + NANO_TO_SEC;
        }
        else
        {
            // Increment PPS and BPS using built-in functions.
            __sync_fetch_and_add(&stats->pps, 1);
            __sync_fetch_and_add(&stats->bps, pkt_len);
        }

        *pps = stats->pps;
        *bps = stats->bps;
    }
    else
    {
        // Create new entry.
        cl_stats_t new = {0};

        new.pps = 1;
        new.bps = pkt_len;
        new.next_update = now + NANO_TO_SEC;

        *pps = new.pps;
        *bps = new.bps;

        bpf_map_update_elem(&map_ip6_stats, ip, &new, BPF_ANY);
    }

    return 0;
}
#endif
#endif

#ifdef ENABLE_RL_FLOW
/**
 * Updates IPv4 flow stats.
 * 
 * @param pps A pointer to the PPS integer.
 * @param bps A pointer to the BPS integer.
 * @param ip The client's source IP.
 * @param port The client's source port.
 * @param protocol The client's protocol.
 * @param pkt_len The total packet length.
 * @param now The current time since boot in nanoseconds.
 * 
 * @return always 0
 */
static __always_inline int update_flow_stats(u64 *pps, u64 *bps, u32 ip, u16 port, u8 protocol, u16 pkt_len, u64 now)
{
    flow_t key = {0};
    key.ip = ip;
    key.port = port;
    key.protocol = protocol;

    cl_stats_t* stats = bpf_map_lookup_elem(&map_flow_stats, &key);

    if (stats)
    {
        // Check for next update.
        if (now > stats->next_update)
        {
            stats->pps = 1;
            stats->bps = pkt_len;
            stats->next_update = now + NANO_TO_SEC;
        }
        else
        {
            // Increment PPS and BPS using built-in functions.
            __sync_fetch_and_add(&stats->pps, 1);
            __sync_fetch_and_add(&stats->bps, pkt_len);
        }

        *pps = stats->pps;
        *bps = stats->bps;
    }
    else
    {
        // Create new entry.
        cl_stats_t new = {0};

        new.pps = 1;
        new.bps = pkt_len;
        new.next_update = now + NANO_TO_SEC;

        *pps = new.pps;
        *bps = new.bps;

        bpf_map_update_elem(&map_flow_stats, &key, &new, BPF_ANY);
    }

    return 0;
}

#ifdef ENABLE_IPV6
/**
 * Updates IPv6 flow stats.
 * 
 * @param pps A pointer to the PPS integer.
 * @param bps A pointer to the BPS integer.
 * @param ip The client's source IP.
 * @param port The client's source port.
 * @param protocol The client's protocol.
 * @param pkt_len The total packet length.
 * @param now The current time since boot in nanoseconds.
 * 
 * @return always 0
 */
static __always_inline int update_flow6_stats(u64 *pps, u64 *bps, u128 *ip, u16 port, u8 protocol, u16 pkt_len, u64 now)
{
    flow6_t key = {0};
    key.ip = *ip;
    key.port = port;
    key.protocol = protocol;

    cl_stats_t* stats = bpf_map_lookup_elem(&map_flow6_stats, &key);

    if (stats)
    {
        // Check for next update.
        if (now > stats->next_update)
        {
            stats->pps = 1;
            stats->bps = pkt_len;
            stats->next_update = now + NANO_TO_SEC;
        }
        else
        {
            // Increment PPS and BPS using built-in functions.
            __sync_fetch_and_add(&stats->pps, 1);
            __sync_fetch_and_add(&stats->bps, pkt_len);
        }

        *pps = stats->pps;
        *bps = stats->bps;
    }
    else
    {
        // Create new entry.
        cl_stats_t new = {0};

        new.pps = 1;
        new.bps = pkt_len;
        new.next_update = now + NANO_TO_SEC;

        *pps = new.pps;
        *bps = new.bps;

        bpf_map_update_elem(&map_flow6_stats, &key, &new, BPF_ANY);
    }

    return 0;
}
#endif
#endif
#endif