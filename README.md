# XDP Firewall
## Description
An XDP firewall designed to read filtering rules based off of a config file. This software only supports IPv4 and protocols TCP, UDP, and ICMP at the moment. With that said, the program comes with accepted and blocked packet statistics which can be disabled if need to be.

Additionally, if the host's NIC doesn't support XDP-native, the program will attempt to attach via XDP generic. The program firstly tries XDP-native, though.

## Command Line Usage
The following command line arguments are supported:

* `--config -c` => Location to config file. Default => **/etc/xdpfw/xdpfw.conf**.
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
* `srcip` => The source IP the packet must match (e.g. 10.50.0.3).
* `dstip` => The destination IP the packet must match (e.g. 10.50.0.4).
* `min_ttl` => The minimum TTL (time to live) the packet must match.
* `max_ttl` => The maximum TTL (time to live) the packet must match.
* `max_len` => The maximum packet length the packet must match. This includes the entire frame (ethernet header, IP header, L4 header, and data).
* `min_len` => The minimum packet length the packet must match. This includes the entire frame (ethernet header, IP header, L4 header, and data).
* `tos` => The TOS (type of service) the packet must match.
* `pps` => The maximum packets per second a source IP can send before matching.
* `bps` => The maximum amount of bytes per second a source IP can send before matching.
* `blocktime` => The time in seconds to block the source IP if the rule matches and the action is block (0). Default value is `1`.
* `payloadmatch` => The payload (L4 data) the packet must have to match. The format is in hexadecimal and each byte is separated by a space. An example includes: `FF FF FF FF 59`.

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

**Note** - As of right now, the `payloadmatch` option does not work. I am planning to implement functionality for this soon. Unfortunately, BPF hasn't liked the matching methods I've used so far.

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

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Creator.