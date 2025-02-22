#pragma once

// Feel free to comment this out if you don't want the `blocked` entry on the stats map to be incremented every single time a packet is dropped from the source IP being on the blocked map. Commenting this line out should increase performance when blocking malicious traffic.
#define DOSTATSONBLOCKMAP

// When this is defined, a check will occur inside the IPv4 and IPv6 filters. For IPv6 packets, if no IPv6 source/destination IP addresses are set, but there is an IPv4 address, it will ignore the filter. The same goes for IPv4, if there is no IPv4 source/destination IP addresses set, if an IPv6 address is set, it will ignore the filter.
#define ALLOWSINGLEIPV4V6

// If uncommented, rate limits for clients are determined using the source IP, port, and protocol instead of just the source IP.
// This allows for more precise rate limits (connection-specific instead of a single source IP).
// I decided not to include the destination IP/port because the source IP, port, and protocol should be represent a unique connection.
#define USE_FLOW_RL