These are scripts to make building and debugging this tool easier. They're used in the main [`install.sh`](../install.sh) file.

* [`build.sh`](./build.sh) - Builds the XDP Firewall tool.
* [`install.sh`](./install.sh) - Installs the XDP Firewall tool to system.
* [`clean.sh`](./clean.sh) - Cleans the XDP Firewall tool's build files.
* [`libxdp_build.sh`](./libxdp_build.sh) - Builds the LibXDP library.
* [`libxdp_install.sh`](./libxdp_install.sh) - Installs the LibXDP library to system.
* [`libxdp_clean.sh`](./libxdp_clean.sh) - Cleans the LibXDP library's build files.
* [`objdump.sh`](./objdump.sh) - Dumps the XDP/BPF object file using `llvm-objdump` to Assemby into `objdump.asm`.