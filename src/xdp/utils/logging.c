#include <linux/ip.h>
#include <linux/ipv6.h>

#include <xdp/utils/helpers.h>
#include <xdp/utils/maps.h>

#if defined(ENABLE_FILTERS) && defined(ENABLE_FILTER_LOGGING)
/**
 * Logs a message to the filter ringbuffer map.
 * 
 * @param iph The IPv4 header.
 * @param iph6 The IPv6 header.
 * @param src_port The source port.
 * @param dst_port The destination port.
 * @param protocol The protocol.
 * @param now The timestamp.
 * @param ip_pps The current IP PPS rate.
 * @param ip_bps The current IP BPS rate.
 * @param flow_pps The current flow PPS rate.
 * @param flow_bps The current flow BPS rate.
 * @param pkt_len The full packet length.
 * @param filter_id The filter ID that matched.
 * 
 * @return always 0
 */
static __always_inline int log_filter_msg(struct iphdr* iph, struct ipv6hdr* iph6, u16 src_port, u16 dst_port, u8 protocol, u64 now, u64 ip_pps, u64 ip_bps, u64 flow_pps, u64 flow_bps, int pkt_len, int filter_id)
{
    filter_log_event_t* e = bpf_ringbuf_reserve(&map_filter_log, sizeof(*e), 0);

    if (e)
    {
        e->ts = now;
        e->filter_id = filter_id;

        if (iph)
        {
            e->src_ip = iph->saddr;
            e->dst_ip = iph->daddr;
        }
#ifdef ENABLE_IPV6
        else if (iph6)
        {
            memcpy(&e->src_ip6, iph6->saddr.in6_u.u6_addr32, 4);
            memcpy(&e->dst_ip6, iph6->daddr.in6_u.u6_addr32, 4);
        }
#endif

        e->src_port = src_port;
        e->dst_port = dst_port;

        e->protocol = protocol;

        e->ip_pps = ip_pps;
        e->ip_bps = ip_bps;

        e->flow_pps = flow_pps;
        e->flow_bps = flow_bps;

        e->length = pkt_len;

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
#endif