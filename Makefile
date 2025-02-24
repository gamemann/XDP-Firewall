CC = clang

LIBXDP_STATIC ?= 0

# Top-level directories.
BUILD_DIR = build
SRC_DIR = src
MODULES_DIR = modules

# Common directories.
COMMON_DIR = $(SRC_DIR)/common
LOADER_DIR = $(SRC_DIR)/loader
XDP_DIR = $(SRC_DIR)/xdp

ETC_DIR = /etc/xdpfw

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

# LibBPF objects.
LIBBPF_OBJS = $(addprefix $(LIBBPF_SRC)/staticobjs/, $(notdir $(wildcard $(LIBBPF_SRC)/staticobjs/*.o)))

# LibXDP objects.
# To Do: Figure out why static objects produces errors relating to unreferenced functions with dispatcher.
# Note: Not sure why shared objects are acting like static objects here where we can link while building and then don't require them at runtime, etc.
LIBXDP_OBJS = $(addprefix $(LIBXDP_DIR)/sharedobjs/, $(notdir $(wildcard $(LIBXDP_DIR)/sharedobjs/*.o)))

# Loader directories.
LOADER_SRC = prog.c
LOADER_OUT = xdpfw

LOADER_UTILS_DIR = $(LOADER_DIR)/utils

# Loader utils.
LOADER_UTILS_CONFIG_SRC = config.c
LOADER_UTILS_CONFIG_OBJ = config.o

LOADER_UTILS_CMDLINE_SRC = cmdline.c
LOADER_UTILS_CMDLINE_OBJ = cmdline.o

LOADER_UTILS_XDP_SRC = xdp.c
LOADER_UTILS_XDP_OBJ = xdp.o

LOADER_UTILS_STATS_SRC = stats.c
LOADER_UTILS_STATS_OBJ = stats.o

LOADER_UTILS_HELPERS_SRC = helpers.c
LOADER_UTILS_HELPERS_OBJ = helpers.o

# Loader objects.
LOADER_OBJS = $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CONFIG_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CMDLINE_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_XDP_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_STATS_OBJ) $(BUILD_LOADER_DIR)/$(LOADER_UTILS_HELPERS_OBJ)

ifeq ($(LIBXDP_STATIC), 1)
	LOADER_OBJS := $(LIBBPF_OBJS) $(LIBXDP_OBJS) $(LOADER_OBJS)
endif

# XDP directories.
XDP_SRC = prog.c
XDP_OBJ = xdp_prog.o

# Includes.
INCS = -I $(SRC_DIR)

ifeq ($(LIBXDP_STATIC), 1)
	INCS += -I $(XDP_TOOLS_HEADERS) -I $(LIBBPF_SRC)
else
	INCS += -I /usr/include -I /usr/local/include
endif

# Flags.
FLAGS = -O2 -g
FLAGS_LOADER = -lconfig -lelf -lz

ifeq ($(LIBXDP_STATIC), 1)
	FLAGS += -D__LIBXDP_STATIC__
else
	FLAGS_LOADER += -lbpf -lxdp
endif

# All chains.
all: loader xdp

# Loader program.
loader: loader_utils
	$(CC) $(INCS) $(FLAGS) $(FLAGS_LOADER) -o $(BUILD_LOADER_DIR)/$(LOADER_OUT) $(LOADER_OBJS) $(LOADER_DIR)/$(LOADER_SRC)

loader_utils: loader_utils_config loader_utils_cmdline loader_utils_helpers loader_utils_xdp loader_utils_stats

loader_utils_config:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CONFIG_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_CONFIG_SRC)

loader_utils_cmdline:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_CMDLINE_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_CMDLINE_SRC)

loader_utils_xdp:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_XDP_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_XDP_SRC)

loader_utils_stats:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_STATS_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_STATS_SRC)

loader_utils_helpers:
	$(CC) $(INCS) $(FLAGS) -c -o $(BUILD_LOADER_DIR)/$(LOADER_UTILS_HELPERS_OBJ) $(LOADER_UTILS_DIR)/$(LOADER_UTILS_HELPERS_SRC)

# XDP program.
xdp:
	$(CC) $(INCS) $(FLAGS) -target bpf -c -o $(BUILD_XDP_DIR)/$(XDP_OBJ) $(XDP_DIR)/$(XDP_SRC)

# LibXDP chain. We need to install objects here since our program relies on installed object files and such.
libxdp:
	$(MAKE) -C $(XDP_TOOLS_DIR) libxdp

libxdp_install:
	$(MAKE) -C $(LIBBPF_SRC) install
	$(MAKE) -C $(LIBXDP_DIR) install

libxdp_clean:
	$(MAKE) -C $(XDP_TOOLS_DIR) clean
	$(MAKE) -C $(LIBBPF_SRC) clean

install:
	mkdir -p $(ETC_DIR)
	cp -n xdpfw.conf.example $(ETC_DIR)/xdpfw.conf

	cp -n other/xdpfw.service /etc/systemd/system/

	cp -f $(BUILD_LOADER_DIR)/$(LOADER_OUT) /usr/bin
	cp -f $(BUILD_XDP_DIR)/$(XDP_OBJ) $(ETC_DIR)

clean:	
	find $(BUILD_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_LOADER_DIR) -type f ! -name ".*" -exec rm -f {} +
	find $(BUILD_XDP_DIR) -type f ! -name ".*" -exec rm -f {} +

.PHONY: all libxdp
.DEFAULT: all