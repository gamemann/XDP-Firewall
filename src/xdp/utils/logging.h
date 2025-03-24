#include <common/all.h>

#include <linux/bpf.h>

#include <xdp/xdp_helpers.h>
#include <xdp/prog_dispatcher.h>

#if defined(ENABLE_FILTERS) && defined(ENABLE_FILTER_LOGGING)
static __always_inline int log_filter_msg(struct iphdr* iph, struct ipv6hdr* iph6, u16 src_port, u16 dst_port, u8 protocol, u64 now, u64 ip_pps, u64 ip_bps, u64 flow_pps, u64 flow_bps, int pkt_len, int filter_id);
#endif

// The source file is included directly below instead of compiled and linked as an object because when linking, there is no guarantee the compiler will inline the function (which is crucial for performance).
// I'd prefer not to include the function logic inside of the header file.
// More Info: https://stackoverflow.com/questions/24289599/always-inline-does-not-work-when-function-is-implemented-in-different-file
#include "logging.c"