PREFIX = /usr/local
DBG = -g -ggdb
INSTALL = install

MAKEFLAGS := --jobs=$(shell nproc)

ARCH = $(shell uname -m | sed 's/x86_64/x86/')

OUTPUT := .output
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath ./$(OUTPUT)/libbpf.a)
LIBBPF_OBJDIR := $(abspath ./$(OUTPUT)/libbpf)
LIBBPF_DESTDIR := $(abspath ./$(OUTPUT))

BPFTOOL = $(abspath ./tools/bpftool)

CC = clang
CLANG = clang
LLVM_STRIP = llvm-strip

INCLUDES := -I$(OUTPUT) -I.

CFLAGS := -g -O2 -Wall
LDFLAGS :=

PROGRAM = mine hijack

all: $(PROGRAM)

$(OUTPUT) $(OUTPUT)/libbpf:
	mkdir -p $@

$(PROGRAM): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(CC) $(CFLAGS) $^ -lelf -lz -o $@

$(patsubst %,$(OUTPUT)/%.o,$(PROGRAM)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c %.h | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) ./vmlinux.h | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		     $(INCLUDES) -c $(filter %.c,$^) -o $@ && \
	$(LLVM_STRIP) -g $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		OBJDIR=$(LIBBPF_OBJDIR) \
		DESTDIR=$(LIBBPF_DESTDIR) \
		INCLUDEDIR= LIBDIR= UAPIDIR= install

clean:
	rm -rf $(OUTPUT) $(PROGRAM)

install: $(PROGRAM)
	$(INSTALL) -m 0755 -d $(DESTDIR)$(prefix)/bin
	$(INSTALL) $(PROGRAM) $(DESTDIR)$(prefix)/bin
