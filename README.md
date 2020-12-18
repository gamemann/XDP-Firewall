# XDP Firewall
## Description
A stateless firewall written using [XDP](https://www.iovisor.org/technology/xdp) designed to read filtering rules based off of a config file and filter incoming packets. Both IPv4 and **IPv6** are supported! Supported protocols include TCP, UDP, and ICMP at the moment. With that said, the program comes with accepted and blocked packet statistics which can be disabled if need to be.

Additionally, if the host's NIC doesn't support XDP-native, the program will attempt to attach via XDP generic. The program firstly tries XDP-native, though.

## Command Line Usage
The following command line arguments are supported:

* `--config -c` => Location to config file. Default => **/etc/xdpfw/xdpfw.conf**.
* `--offload -o` => Tries to load the XDP program in hardware/offload mode.
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
The config option `tcpopts` within a filter is an array including TCP options. This should only be one array per filter. Options include:

* `enabled` => If true, check for TCP-specific matches.
* `sport` => The source port the packet must match.
* `dport` => The destination port the packet must match.
* `urg` => If true, the packet must have the `URG` flag set to match.
* `ack` => If true, the packet must have the `ACK` flag set to match.
* `rst` => If true, the packet must have the `RST` flag set to match.
* `psh` => If true, the packet must have the `PSH` flag set to match.
* `syn` => If true, the packet must have the `SYN` flag set to match.
* `fin` => If true, the packet must have the `FIN` flag set to match.

#### UDP Options

The config option `udpopts` within a filter is an array including UDP options. This should only be one array per filter. Options include:

* `enabled` => If true, check for UDP-specific matches.
* `sport` => The source port the packet must match.
* `dport` => The destination port the packet must match.

#### ICMP Options

The config option `icmpopts` within a filter is an array including ICMP options. This should only be one array per filter. Options include:

* `enabled` => If true, check for ICMP-specific matches.
* `code` => The ICMP code the packet must match.
* `type` => The ICMP type the packet must match.

**Note** - Everything besides the main `enabled` and `action` options within a filter are **not** required. This means you do not have to define them within your config.

**Note** - As of right now, you can specify up to 55 maximum filters. This is due to the BPF map's max entries limitation while using `BPF_MAP_TYPE_ARRAY`. I don't believe we'd be able to use a per-CPU map for this as well because if we do, I don't believe we'd be able to reliably read the filters within the XDP program. If you want more filters, you could try using a hash map (changing the filter map's type to `BPF_MAP_TYPE_HASH`), but keep in mind lookups on the filters will be slower.

## Configuration Example
Here's an example of a config:

```
interface = "ens18";
updatetime = 15;

filters = (
    {
        enabled = true,
        action = 0,

        udpopts = (
            {
                enabled = true,
                dport = 27015
            }
        )
    },
    {
        enabled = true,
        action = 1,

        tcpopts = (
            {
                enabled = true,
                syn = true,
                dport = 27015
            }
        )
    },
    {
        enabled = true,
        action = 0,

        icmpopts = (
            {
                enabled = true,
                code = 0
            }
        )
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

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Creator.