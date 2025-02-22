CC = clang

# Top-level directories.
BUILD_DIR = build
SRC_DIR = src
MODULES_DIR = modules

# Common directories.
COMMON_DIR = $(SRC_DIR)/common
LOADER_DIR = $(SRC_DIR)/loader
XDP_DIR = $(SRC_DIR)/xdp

# Additional build directories.
BUILD_LOADER_DIR = $(BUILD_DIR)/loader
BUILD_XDP_DIR = $(BUILD_DIR)/xdp

# XDP Tools directories.
XDP_TOOLS_DIR = $(MODULES_DIR)/xdp-tools
XDP_TOOLS_HEADERS = $(XDP_TOOLS_DIR)/headers

# LibXDP and LibBPF directories.
LIBXDP_DIR = $(XDP_TOOLS_DIR)/lib/libxdp
LIBBPF_DIR = $(XDP_TOOLS_DIR)/lib/libbpf

LIBBPF_SRC = $(LIBBPF_DIR)/src

# Loader directories.
LOADER_SRC = loader.c
LOADER_OUT = xdpfw

LOADER_UTILS_DIR = $(LOADER_DIR)/utils

# Loader utils.
LOADER_UTILS_CONFIG_SRC = config.c
LOADER_UTILS_CONFIG_OBJ = config.o

LOADER_UTILS_CMDLINE_SRC = cmdline.c
LOADER_UTILS_CMDLINE_OBJ = cmdline.o

LOADER_UTILS_HELPERS_SRC = helpers.c
LOADER_UTILS_HELPERS_OBJ = helpers.o

# Loader objects.
LOADER_OBJS = $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CONFIG_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CMDLINE_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_HELPERS_OBJ)

# XDP directories.
XDP_SRC = prog.c
XDP_OBJ = xdp_prog.o

XDP_UTILS_DIR = $(XDP_DIR)/utils

# XDP utils.
XDP_UTILS_HELPERS_SRC = helpers.c
XDP_UTILS_HELPERS_OBJ = helpers.o

XDP_UTILS_RL_SRC = rl.c 
XDP_UTILS_RL_OBJ = rl.o

# Includes.
INCS = -I $(SRC_DIR) -I $(LIBBPF_SRC) -I /usr/include -I /usr/local/include

# Flags.
FLAGS = -O2 -g
FLAGS_LOADER = -lconfig -lelf -lz -lbpf -lxdp

# All chains.
all: loader xdp

# Loader program.
loader: libxdp loader_utils
	$(CC) $(INCS) $(FLAGS) $(FLAGS_LOADER) -o $(BUILD_LOADER_DIR)/$(LOADER_OUT) $(LOADER_OBJS) $(LOADER_DIR)/$(LOADER_SRC)

loader_utils: loader_utils_config loader_utils_cmdline loader_utils_helpers

loader_utils_config:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CONFIG_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_CONFIG_SRC)

loader_utils_cmdline:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CMDLINE_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_CMDLINE_SRC)

loader_utils_helpers:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_HELPERS_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_HELPERS_SRC)

# XDP program.
xdp:
	$(CC) $(INCS) $(FLAGS) -target bpf -c -o $(BUILD_XDP_DIR)/$(XDP_OBJ) $(XDP_DIR)/$(XDP_SRC)

# LibXDP chain. We need to install objects here since our program relies on installed object files and such.
libxdp:
	$(MAKE) -C $(XDP_TOOLS_DIR) libxdp
	sudo $(MAKE) -C $(LIBBPF_SRC) install
	sudo $(MAKE) -C $(LIBXDP_DIR) install

clean:
	$(MAKE) -C $(XDP_TOOLS_DIR) clean
	$(MAKE) -C $(LIBBPF_SRC) clean
	
	find $(BUILD_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_LOADER_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_XDP_DIR) -type f ! -name ".*" -exec rm -f {} +

install:
	mkdir -p /etc/xdpfw/
	cp -n xdpfw.conf.example /etc/xdpfw/xdpfw.conf

	cp -f $(BUILD_LOADER_DIR)/$(LOADER_OUT) /usr/bin
	cp -f $(BUILD_XDP_DIR)/$(XDP_OBJ) /etc/xdpfw

	cp -n other/xdpfw.service /etc/systemd/system/

.PHONY: all libxdp
.DEFAULT: all