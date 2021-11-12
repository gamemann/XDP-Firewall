# XDP Firewall
## Description
A stateless firewall that attaches to the [XDP](https://www.iovisor.org/technology/xdp) hook for fast packet processing. This firewall is designed to read filtering rules based off of a config file and filter incoming packets. Both IPv4 and **IPv6** are supported! Supported protocols include TCP, UDP, and ICMP at the moment. With that said, the program comes with accepted and blocked packet statistics which can be disabled if need to be.

Additionally, if the host's NIC doesn't support XDP DRV hook (AKA native), the program will attempt to attach to the XDP SKB hook (AKA generic). The program firstly tries XDP DRV mode, though.

## Command Line Usage
The following command line arguments are supported:

* `--config -c` => Location to config file. Default => **/etc/xdpfw/xdpfw.conf**.
* `--offload -o` => Tries to load the XDP program in hardware/offload mode.
* `--skb -s` => Forces the program to load in SKB mode instead of DRV.
* `--list -l` => List all filtering rules scanned from config file.
* `--help -h` => Print help menu for command line options.

## Configuration File Options
### Main
* `interface` => The interface for the XDP program to attach to.
* `updatetime` => How often to update the config and filtering rules. Leaving this at 0 disables auto-updating.
* `nostats` => If true, no accepted/blocked packet statistics will be displayed in `stdout`.

### Filters
Config option `filters` is an array. Each filter includes the following options:

* `enabled` => If true, this rule is enabled.
* `action` => What action to perform against the packet if matched. 0 = Block. 1 = Allow.
* `srcip` => The source IP address the packet must match (e.g. 10.50.0.3).
* `dstip` => The destination IP address the packet must match (e.g. 10.50.0.4).
* `srcip6` => The source IPv6 address the packet must match (e.g. fe80::18c4:dfff:fe70:d8a6).
* `dstip6` => The destination IPv6 address the packet must match (e.g. fe80::ac21:14ff:fe4b:3a6d).
* `min_ttl` => The minimum TTL (time to live) the packet must match.
* `max_ttl` => The maximum TTL (time to live) the packet must match.
* `max_len` => The maximum packet length the packet must match. This includes the entire frame (ethernet header, IP header, L4 header, and data).
* `min_len` => The minimum packet length the packet must match. This includes the entire frame (ethernet header, IP header, L4 header, and data).
* `tos` => The TOS (type of service) the packet must match.
* `pps` => The maximum packets per second a source IP can send before matching.
* `bps` => The maximum amount of bytes per second a source IP can send before matching.
* `blocktime` => The time in seconds to block the source IP if the rule matches and the action is block (0). Default value is `1`.

#### TCP Options
TCP options exist in the main filter array and start with `tcp_`. Please see below.

* `tcp_enabled` => If true, check for TCP-specific matches.
* `tcp_sport` => The source port the packet must match.
* `tcp_dport` => The destination port the packet must match.
* `tcp_urg` => If true, the packet must have the `URG` flag set to match.
* `tcp_ack` => If true, the packet must have the `ACK` flag set to match.
* `tcp_rst` => If true, the packet must have the `RST` flag set to match.
* `tcp_psh` => If true, the packet must have the `PSH` flag set to match.
* `tcp_syn` => If true, the packet must have the `SYN` flag set to match.
* `tcp_fin` => If true, the packet must have the `FIN` flag set to match.

#### UDP Options
UDP options exist in the main filter array and start with `udp_`. Please see below.

* `udp_enabled` => If true, check for UDP-specific matches.
* `udp_sport` => The source port the packet must match.
* `udp_dport` => The destination port the packet must match.

#### ICMP Options
ICMP options exist in the main filter array and start with `icmp_`. Please see below.

* `icmp_enabled` => If true, check for ICMP-specific matches.
* `icmp_code` => The ICMP code the packet must match.
* `icmp_type` => The ICMP type the packet must match.

**Note** - Everything besides the main `enabled` and `action` options within a filter are **not** required. This means you do not have to define them within your config.

**Note** - As of right now, you can specify up to 100 maximum filters. This is due to BPF's max jump limit within the while loop.

## Configuration Example
Here's an example of a config:

```
interface = "ens18";
updatetime = 15;

filters = (
    {
        enabled = true,
        action = 0,

        udp_enabled = true,
        udp_dport = 27015
    },
    {
        enabled = true,
        action = 1,

        tcp_enabled = true,
        tcp_syn = true,
        tcp_dport = 27015
    },
    {
        enabled = true,
        action = 0,

        icmp_enabled = true,
        icmp_code = 0
    },
    {
        enabled = true,
        action = 0,
        srcip = "10.50.0.4"
    }
);
```

## Building
Before building, ensure the `libconfig-dev` package is installed along with necessary building tools such as `llvm`, `clang`, and `libelf-dev`. For Debian/Ubuntu, you can install this with the following as root:

```
apt-get install libconfig-dev
```

You can use `git` and `make` to build this project. The following should work:

```
git clone --recursive https://github.com/gamemann/XDP-Firewall.git
cd XDP-Firewall
make && make install
```

## Notes
### BPF For/While Loop Support
This project requires for/while loop support with BPF. Older kernels will not support this and output an error such as:

```
libbpf: load bpf program failed: Invalid argument
libbpf: -- BEGIN DUMP LOG ---
libbpf:
back-edge from insn 113 to 100

libbpf: -- END LOG --
libbpf: failed to load program 'xdp_prog'
libbpf: failed to load object '/etc/xdpfw/xdpfw_kern.o'
```

**Note** - It looks like BPF while/for loop [support](https://lwn.net/Articles/794934/) was added in kernel 5.3. Therefore, you'll need kernel 5.3 or above for this program to run properly.

## Other XDP Project(s)
I just wanted to share other project(s) I've made using XDP for those interested.

### XDP Forwarding
This XDP project performs basic layer 3/4 forwarding using source port mapping similar to IPTables/NFTables. This is one of my newer projects and still a work in progress. I also feel the code is a lot neater in the XDP Forwarding project.

[GitHub Repository](https://github.com/gamemann/XDP-Forwarding)

## Credits
* [Christian Deacon](https://github.com/gamemann) - Creator.