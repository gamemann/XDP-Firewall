# XDP Firewall
[![XDP Firewall Build Workflow](https://github.com/gamemann/XDP-Firewall/actions/workflows/build.yml/badge.svg)](https://github.com/gamemann/XDP-Firewall/actions/workflows/build.yml) [![XDP Firewall Run Workflow](https://github.com/gamemann/XDP-Firewall/actions/workflows/run.yml/badge.svg)](https://github.com/gamemann/XDP-Firewall/actions/workflows/run.yml)

## Description
A *stateless* firewall that attaches to the Linux kernel's [XDP](https://www.iovisor.org/technology/xdp) hook through [(e)BPF](https://ebpf.io/) for fast packet processing. This firewall is designed to read filtering rules based off of a config file on disk and filter incoming packets. Both IPv4 and **IPv6** are supported! The protocols currently supported are TCP, UDP, and ICMP. With that said, the program comes with accepted and dropped/blocked packet statistics which may be disabled if need to be.

Additionally, if the host's network configuration or network interface card (NIC) doesn't support the XDP DRV hook (AKA native; occurs before [SKB creation](http://vger.kernel.org/~davem/skb.html)), the program will attempt to attach to the XDP SKB hook (AKA generic; occurs after SKB creation which is where IPTables and NFTables are processed via the `netfilter` kernel module). You may use overrides through the command-line to force SKB or offload modes.

With that said, reasons for a host's network configuration not supporting XDP's DRV hook may be the following.

* Running an outdated kernel that doesn't support your NIC's driver.
* Your NIC's driver not yet being supported. [Here's](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp) a NIC driver XDP support list. With enough Linux kernel development knowledge, you could try implementing XDP DRV support into your non-supported NIC's driver (I'd highly recommend giving [this](https://www.youtube.com/watch?v=ayFWnFj5fY8) video a watch!).
* You don't have enough RX/TX queues (e.g. not enabling multi-queue) or your RX/TX queue counts aren't matching. From the information I gathered, it's recommended to have one RX and TX queue per CPU core/thread. You could try learning how to use [ethtool](https://man7.org/linux/man-pages/man8/ethtool.8.html) and try altering the NIC's RX/TX queue settings ([this](https://www.linode.com/docs/guides/multiqueue-nic/) article may be helpful!).

I hope this project helps existing network engineers/programmers interested in utilizing XDP or anybody interested in getting into those fields! (D)DoS mitigation/prevention is such an important part of Cyber Security and understanding the concept of networking and packet flow on a low-medium level would certainly help those who are pursuing a career in the field 🙂

## Command Line Usage
The following command line arguments are supported:

* `--config -c` => Location to config file. Default => **/etc/xdpfw/xdpfw.conf**.
* `--offload -o` => Tries to load the XDP program in hardware/offload mode (please read **Offload Information** below).
* `--skb -s` => Forces the program to load in SKB mode instead of DRV.
* `--time -t` => How long to run the program for in seconds before exiting. 0 or not set = infinite.
* `--list -l` => List all filtering rules scanned from config file.
* `--help -h` => Print help menu for command line options.

### Offload Information
Offloading your XDP/BPF program to your system's NIC allows for the fastest packet processing you can achieve due to the NIC dropping the packets with its hardware. However, for one, there are **not** many NIC manufacturers that do support this feature **and** you're limited to the NIC's memory/processing (e.g. your BPF map sizes will be extremely limited). Additionally, there are usually stricter BPF verifier limitations for offloaded BPF programs, but you may try reaching out to the NIC's manufacturer to see if they will give you a special version of their NIC driver raising these limitations (this is what I did with one manufacturer I used).

As of this time, I am not aware of any NIC manufacturers that will be able to offload this firewall completely to the NIC due to its BPF complexity. To be honest, in the current networking age, I believe it's best to leave offloaded programs to BPF map lookups and minimum packet inspection. For example, a BPF blacklist map lookup for malicious source IPs or ports. However, XDP is still very new and I would imagine we're going to see these limitations loosened or lifted in the next upcoming years. This is why I added support for offload mode on this firewall. 

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
* `tcp_ece` => If true, the packet must have the `ECE` flag set to match.
* `tcp_cwr` => If true, the packet must have the `CWR` flag set to match.

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

Everything besides the main `enabled` and `action` options within a filter are **not** required. This means you do not have to define them within your config.

**Note** - As of right now, you can specify up to 100 maximum filters. This is due to BPF's max jump limit within the while loop.

## Configuration Example
Here's an example of a config:

```squidconf
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

## Building & Installation
Before building, ensure the `libconfig-dev` package is installed along with necessary building tools such as `llvm`, `clang`, and `libelf-dev`. For Debian/Ubuntu, you can install this with the following as root:

```bash
# Install dependencies.
apt-get install libconfig-dev llvm clang libelf-dev build-essential -y
```

You can use `git` and `make` to build this project. The following should work:

```bash
# Clone repository via Git. Use recursive flag to download LibBPF sub-module.
git clone --recursive https://github.com/gamemann/XDP-Firewall.git

# Change directory to repository.
cd XDP-Firewall

# Build project and install as root via Sudo.
make && sudo make install
```

## Notes
### BPF For/While Loop Support
This project requires for/while loop support with BPF. Older kernels will not support this and output an error such as:

```vim
libbpf: load bpf program failed: Invalid argument
libbpf: -- BEGIN DUMP LOG ---
libbpf:
back-edge from insn 113 to 100

libbpf: -- END LOG --
libbpf: failed to load program 'xdp_prog'
libbpf: failed to load object '/etc/xdpfw/xdpfw_kern.o'
```

It looks like BPF while/for loop [support](https://lwn.net/Articles/794934/) was added in kernel 5.3. Therefore, you'll need kernel 5.3 or above for this program to run properly.

**NOTE** - Due to the use of loops inside this XDP program, it's likely performance won't be as fast as XDP programs that use BPF map lookups directly. This firewall was designed to be as flexible as possible in regards to configuration. Therefore, in that case, we can't really use BPF maps via key lookup unless if we insert **many** entries inside of the maps themselves which is less than ideal for how much configuration we allow.

### Will You Make This Firewall Stateful?
There is a possibility I may make this firewall stateful in the future *when* I have time, but this will require a complete overhaul along with implementing application-specific filters. With that said, I am still on contract from my previous employers for certain filters of game servers. If others are willing to contribute to the project and implement these features, feel free to make pull requests!

You may also be interested in this awesome project called [FastNetMon](https://github.com/pavel-odintsov/fastnetmon)!

## Other XDP Project(s)
I just wanted to share other project(s) I've made using XDP for those interested.

### XDP Forwarding
This XDP project performs basic layer 3/4 forwarding using source port mapping similar to IPTables/NFTables. This is one of my newer projects and still a work in progress. I also feel the code is a lot neater in the XDP Forwarding project.

[GitHub Repository](https://github.com/gamemann/XDP-Forwarding)

## Credits
* [Christian Deacon](https://github.com/gamemann) - Creator.
* [Phil](https://github.com/Nasty07) - Contributor.
