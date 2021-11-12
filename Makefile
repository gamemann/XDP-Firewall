CC = clang

BUILDDIR = build
SRCDIR = src

LIBBPFSRC = libbpf/src
LIBBPFOBJS = $(LIBBPFSRC)/staticobjs/bpf_prog_linfo.o $(LIBBPFSRC)/staticobjs/bpf.o $(LIBBPFSRC)/staticobjs/btf_dump.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/btf.o $(LIBBPFSRC)/staticobjs/gen_loader.o $(LIBBPFSRC)/staticobjs/hashmap.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/libbpf_errno.o $(LIBBPFSRC)/staticobjs/libbpf_probes.o $(LIBBPFSRC)/staticobjs/libbpf.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/linker.o $(LIBBPFSRC)/staticobjs/netlink.o $(LIBBPFSRC)/staticobjs/nlattr.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/relo_core.o $(LIBBPFSRC)/staticobjs/ringbuf.o $(LIBBPFSRC)/staticobjs/str_error.o
LIBBPFOBJS += $(LIBBPFSRC)/staticobjs/strset.o $(LIBBPFSRC)/staticobjs/xsk.o

CONFIGSRC = config.c
CONFIGOBJ = config.o

XDPFWSRC = xdpfw.c
XDPFWOUT = xdpfw

XDPPROGSRC = xdpfw_kern.c
XDPPROGBC = xdpfw_kern.bc
XDPPROGOBJ = xdpfw_kern.o

OBJS = $(BUILDDIR)/$(CONFIGOBJ)

LDFLAGS += -lconfig -lelf -lz
INCS = -I $(LIBBPFSRC)

all: xdpfw xdpfw_filter utils
xdpfw: utils libbpf $(OBJS)
	mkdir -p $(BUILDDIR)/
	$(CC) $(LDFLAGS) $(INCS) -o $(BUILDDIR)/$(XDPFWOUT) $(LIBBPFOBJS) $(OBJS) $(SRCDIR)/$(XDPFWSRC)
xdpfw_filter:
	mkdir -p $(BUILDDIR)/
	$(CC) $(INCS) -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c -o $(BUILDDIR)/$(XDPPROGBC) $(SRCDIR)/$(XDPPROGSRC)
	llc -march=bpf -filetype=obj -o $(BUILDDIR)/$(XDPPROGOBJ) $(BUILDDIR)/$(XDPPROGBC)
utils:
	mkdir -p $(BUILDDIR)/
	$(CC) -O2 -c $(LDFLAGS) -o $(BUILDDIR)/$(CONFIGOBJ) $(SRCDIR)/$(CONFIGSRC)
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -f $(BUILDDIR)/*.o $(BUILDDIR)/*.bc
	rm -f $(BUILDDIR)/$(XDPFWOUT)
install:
	mkdir -p /etc/xdpfw/
	cp -n xdpfw.conf.example /etc/xdpfw/xdpfw.conf
	cp $(BUILDDIR)/$(XDPPROGOBJ) /etc/xdpfw/$(XDPPROGOBJ)
	cp $(BUILDDIR)/$(XDPFWOUT) /usr/bin/$(XDPFWOUT)
	cp -n other/xdpfw.service /etc/systemd/system/
.PHONY: libbpf all
.DEFAULT: all