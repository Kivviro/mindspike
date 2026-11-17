CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
    BPF_ARCH := x86
else ifeq ($(ARCH),aarch64)
    BPF_ARCH := arm64
else
    $(error Unsupported architecture: $(ARCH))
endif

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -I.

all: sudo_watch

vmlinux.h:
	$(BPFTOOL) btf dump file \
		/sys/kernel/btf/vmlinux format c > $@

sudo_watch.bpf.o: sudo_watch.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
		-c $< -o $@

sudo_watch.skel.h: sudo_watch.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

sudo_watch: sudo_watch.c sudo_watch.skel.h
	$(CC) -O2 -g $(LIBBPF_CFLAGS) sudo_watch.c -o $@ $(LIBBPF_LIBS)

clean:
	rm -f sudo_watch sudo_watch.bpf.o sudo_watch.skel.h vmlinux.h

.PHONY: all clean
