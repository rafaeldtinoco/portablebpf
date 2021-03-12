OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= ./tools/bpftool
LIBBPF_SRC := $(abspath ./libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT) -I.
CFLAGS := -g -O2 -Wall
INSTALL ?= install
prefix ?= /usr/local
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APPS = mine

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf:
	mkdir -p $@

$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(CC) $(CFLAGS) -DNOTBCC  $^ -lelf -lz -o $@

$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(CC) $(CFLAGS) $(INCLUDES) -DNOTBCC -c $(filter %.c,$^) -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) ./vmlinux.h | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -DNOTBCC	\
		     $(INCLUDES) -c $(filter %.c,$^) -o $@ &&		\
	$(LLVM_STRIP) -g $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1			\
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		\
		    INCLUDEDIR= LIBDIR= UAPIDIR=			\
		    install

.DELETE_ON_ERROR:

.SECONDARY:
