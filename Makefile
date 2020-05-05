CC = clang

objects += src/config.o src/xdpfw_loader.o

libbpf_static_objects += libbpf/src/staticobjs/bpf.o libbpf/src/staticobjs/btf.o libbpf/src/staticobjs/libbpf_errno.o libbpf/src/staticobjs/libbpf_probes.o
libbpf_static_objects += libbpf/src/staticobjs/libbpf.o libbpf/src/staticobjs/netlink.o libbpf/src/staticobjs/nlattr.o libbpf/src/staticobjs/str_error.o
libbpf_static_objects += libbpf/src/staticobjs/hashmap.o libbpf/src/staticobjs/bpf_prog_linfo.o

LDFLAGS += -lconfig -lelf -lz

all: xdpfw_loader xdpfw_filter
xdpfw_loader: libbpf $(objects)
	clang $(LDFLAGS) -o xdpfw $(libbpf_static_objects) $(objects)
xdpfw_filter: src/xdpfw_kern.o
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/xdpfw_kern.c -o src/xdpfw_kern.bc
	llc -march=bpf -filetype=obj src/xdpfw_kern.bc -o src/xdpfw_kern.o
libbpf:
	$(MAKE) -C libbpf/src
clean:
	$(MAKE) -C libbpf/src clean
	rm -f src/*.o src/*.bc
	rm -f xdpfw_loader
install:
	mkdir -p /etc/xdpfw/
	cp -n xdpfw.conf.example /etc/xdpfw/xdpfw.conf
	cp src/xdpfw_kern.o /etc/xdpfw/xdpfw_kern.o
	cp xdpfw /usr/bin/xdpfw
	cp -n other/xdpfw.service /etc/systemd/system/
.PHONY: libbpf all
.DEFAULT: all