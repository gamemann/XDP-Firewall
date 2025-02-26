#pragma once

// The maximum amount of filters allowed.
// Decrease this value if you receive errors related to the BPF program being too large.
#define MAX_FILTERS 60

// The maximum amount of IPs/flows to track stats for.
// The higher this value is, the more memory that'll be used.
#define MAX_TRACK_IPS 100000

// Feel free to comment this out if you don't want the `blocked` entry on the stats map to be incremented every single time a packet is dropped from the source IP being on the blocked map.
// Commenting this line out should increase performance when blocking malicious traffic.
#define DO_STATS_ON_BLOCK_MAP

// When this is defined, a check will occur inside the IPv4 and IPv6 filters.
// For IPv6 packets, if no IPv6 source/destination IP addresses are set, but there is an IPv4 address, it will ignore the filter.
// The same goes for IPv4, if there is no IPv4 source/destination IP addresses set, if an IPv6 address is set, it will ignore the filter.
#define ALLOW_SINGLE_IP_V4_V6

// If uncommented, rate limits for clients are determined using the source IP, port, and protocol instead of just the source IP.
// This allows for more precise rate limits (connection-specific instead of a single source IP).
// I decided not to include the destination IP/port because the source IP, port, and protocol should be represent a unique connection.
#define USE_FLOW_RL

// Enables filter logging through XDP.
// If performance is a concerned, it is best to disable this feature by commenting out the below line with //.
#define ENABLE_FILTER_LOGGING