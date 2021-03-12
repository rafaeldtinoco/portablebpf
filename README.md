# eBPF CO.RE code example
### bonus 1: compatible with BCC<BR>bonus 2: userland portion in C and Python<BR>bonus 3: compatible with v4.x.y kernels

My original intent was to create an eBPF code that could be oded in C and be portable among different kernels. I had a specific project in mind - [ipsetaudit](https://github.com/rafaeldtinoco/ipsetaudit), a tool capable of auditing calls to ipset - and during the development there were so many caveats - that had to be investigated in mailing lists or using the old try-n-error approach - I decided to document them here with a code example that could be used by anyone willing to create an eBPF tool from the beginning.

## eBPF libraries

There are currently 2 main eBPF libraries:

1. BCC: compiles the eBPF code during code execution, loads the eBPF bytecode in kernel and makes userland app to get shared information from the eBPF code through BPF MAPS.

    - [BCC project](https://github.com/iovisor/bcc)
    - [BCC reference guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
    - [BCC python developer](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md)

2. libbpf: compiles the eBPF (and user-land) code before the execution. The library is responsible for making eBPF bytecode symbol relocations BEFORE loading it into kernel, making the binary portable among different kernels. For that, libbpf needs kernel to support BTF (latest kernels support).

    - [libbpf project](https://github.com/libbpf/libbpf)
    - [BPF portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)
    - [BCC to BPF conversion](https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html)

And this example uses the 2:

1. BCC: **mine.py**: a BCC based python app that will compile the same bpf code (ipsetaudit.bpf.c) during its runtime.
 
2. libbpf: **mine**: a pre-compiled and portable libcc based binary with bpf bytecode embedded on it. This binary will be able to run in any kernel supporting BTF.

    - [Diving into BPF](https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/)
    - [Kernel eBPF features by version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
    - [Older kernels and eBPF global data](https://lwn.net/Articles/784936/)

## The file tree explained

**Makefile**

Will magically generate a binary called "mine", statically linkedin with libbpf library (downloaded as a git submodule of this tree).

> This binary will be portable and executed in any kernel supporting BTF (there is a trick[1] to make the same binary to work in kernels not supporting BTF, like the v4.x ones). It already contains the eBPF bytecode on it.

**mine.bpf.c**

This is the **eBPF source code**. It will generate the bytecode that will be executed inside the kernel BPF virtual machine. When coding eBPF programs, one usually uses either the **BPFCC (old BCC)** or, the most recent, **libbpf** library. _This example is compatible with both_. If you are an eBPF tool that is only going to run in newer kernels you would stick with **libbpf** only.

> In this example we have a single kernel probe declared that will be fired everytime the **ip_set_create** kernel function is called. This was chosen because in order for me to get *ipset* events I had to see what functions were called by the netlink handlers whenever a netlink message of ipset type were received by kernel.

> This file is part of the libbpf binary AND compiled during the python script execution (so it has to support the 2 libraries: BCC and libbpf).

**mine.c**

This is the userland portion of my eBPF tool. This is a regular user-land code made in C but, in this case, for the way we are building it, it shares code with a common - to the eBPF code - header file (mine.h). This code is responsible to get information out of BPF maps - shared among the eBPF code, running inside the kernel, and the user-land code and deal with it.

> This file is part of the libbpf binary only.

**mine.h**

This is header file that is shared among the 2 codes: the eBPF C code, in mine.bpf.c, and the userland C code, in mine.c.

> If you are using libbpf only, then this file won't have much but the structs responsible to describe the BPF maps you want to share among kerne and userland.

**mine.py**

This is the python script that uses libbpfcc under the hoods (instead of using libbpf). It will compile the **mine.bpf.c** file during its execution and load the result inside the kernel before the python code actually runs.

**patches/***

Contains patch(es) for some workarounds to get the libcc version of this example tool in older kernels. If you are running this in a recent kernel, there is no need to continue reading this item.

[1] trick: as stated before, if you are running this in an older kernel it won't support BTF. Without getting into too many details, BTF is a very simple and small way to inform about all needed rellocations a pre-compiled eBPF bytecode would need for the current running kernel.

If you run: ```tools/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h``` in a recent kernel you will get a header file describing all existing types for the current kernel, for example.

> I have made some tricks in this example to make sure the libbpf binary would also be portable to a 4.x kernel. So, by using the trick described here, you will be able to compile a single binary and run it in a v4.15 kernel and a v5.8 kernel, without recompiling it.
>
> If you are curious, check mine.c and search for **attach_kprobe_legacy()** function.

So, let's say you want to have a bionic kernel compatible to libbpf generated binaries. You can apply the patch **patches/link-vmlinuz.sh.patch** to its kernel tree and recompile the kernel. Once that is done, you can:

```llvm-objcopy-10 --only-section=.BTF --set-section-flags .BTF=alloc,readonly --strip-all .tmp_vmlinux.btf /boot/vmlinux-4.x.y```

This command will extract the .BTF ELF section out of the .tmp_vmlinux.btf file (vmlinux binary will also contain it if you are installing a dbg package, for example) to a new file called /boot/vmlinux-4.x.y.

This name was chosen because libbpf checks for ELF files containg BTF section in the following paths:

```C
locations[] = {
    /* try canonical vmlinux BTF through sysfs first */
    { "/sys/kernel/btf/vmlinux", true /* raw BTF */ },
    /* fall back to trying to find vmlinux ELF on disk otherwise */
    { "/boot/vmlinux-%1$s" },
    { "/lib/modules/%1$s/vmlinux-%1$s" },
    { "/lib/modules/%1$s/build/vmlinux" },
    { "/usr/lib/modules/%1$s/kernel/vmlinux" },
    { "/usr/lib/debug/boot/vmlinux-%1$s" },
    { "/usr/lib/debug/boot/vmlinux-%1$s.debug" },
    { "/usr/lib/debug/lib/modules/%1$s/vmlinux" },
};
```

You could also stick with /usr/lib/debug/boot/vmlinux file as well (if you want to have debug symbols installed in the same host). The difference is that the BTF section only file is at ~90% the size of the regular vmlinux file containing all symbols =).

> Again, this is ONLY **NEEDED FOR KERNELS NOT SUPPORTING BTF**.

**vmlinux.h**

This file is generated by doing:

```tools/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h``` 
in a kernel supporting BTF.

> you can follow the previous item approach for older kernels and execute:

```tools/bpftool btf dump file /boot/vmlinux-4.x.y format c > vmlinux.h``` 

# Compilation and Execution

## Executing the python based BCC tool

Run the python script in one shell:

```
[rafaeldtinoco@IBM portablebpf]$ sudo ./mine.py
Tracing... Hit Ctrl-C to end.
ipset (pid: 29166) (auid: 1000) - CREATE test123 (type: hash:ip)
ipset (pid: 29167) (auid: 1000) - CREATE test456 (type: hash:ip)
ipset (pid: 29168) (auid: 1000) - CREATE test789 (type: hash:ip)
```

> It will compile **mine.bpf.c** on demand (as BCC does)

During its runtime, it will catch all ipset creations. You can test it by simply running:

```$ sudo ipset create test123 hash:ip```

## Compiling libbpf based binary

Run **make** and it will compile the **mine** binary file:

```
[rafaeldtinoco@fujitsu portablebpf]$ make -j20
mkdir -p .output
mkdir -p .output/libbpf
make -C /home/rafaeldtinoco/devel/portablebpf/libbpf/src BUILD_STATIC_ONLY=1			\
	    OBJDIR=/home/rafaeldtinoco/devel/portablebpf/.output//libbpf DESTDIR=/home/rafaeldtinoco/devel/portablebpf/.output/		\
	    INCLUDEDIR= LIBDIR= UAPIDIR=			\
	    install
make[1]: Entering directory '/home/rafaeldtinoco/devel/portablebpf/libbpf/src'
  MKDIR    staticobjs
  INSTALL  bpf.h libbpf.h btf.h xsk.h libbpf_util.h bpf_helpers.h bpf_helper_defs.h bpf_tracing.h bpf_endian.h bpf_core_read.h libbpf_common.h
  CC       bpf.o
  CC       btf.o
  CC       libbpf.o
  CC       libbpf_errno.o
  CC       netlink.o
  CC       nlattr.o
  CC       str_error.o
  CC       libbpf_probes.o
  CC       bpf_prog_linfo.o
  CC       xsk.o
  CC       btf_dump.o
  CC       hashmap.o
  CC       ringbuf.o
  INSTALL  libbpf.pc
  AR       libbpf.a
  INSTALL  libbpf.a
make[1]: Leaving directory '/home/rafaeldtinoco/devel/portablebpf/libbpf/src'
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -DNOTBCC	\
	     -I.output -I. -c mine.bpf.c -o .output/mine.bpf.o &&		\
llvm-strip -g .output/mine.bpf.o
./tools/bpftool gen skeleton .output/mine.bpf.o > .output/mine.skel.h
cc -g -O2 -Wall -I.output -I. -DNOTBCC -c mine.c -o .output/mine.o
cc -g -O2 -Wall -DNOTBCC  .output/mine.o /home/rafaeldtinoco/devel/portablebpf/.output/libbpf.a -lelf -lz -o mine
```

After the compilation I can execute it in **ANY MACHINE** running a recent enough kernel - supporting BTF - without recompiling it:

```
[rafaeldtinoco@fujitsu portablebpf]$ uname -a
Linux fujitsu 5.8.0-43-generic #49-Ubuntu SMP Fri Feb 5 03:01:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

[rafaeldtinoco@fujitsu portablebpf]$ sudo ./mine -v
Tracing... Hit Ctrl-C to end.
(2021/03/12_17:33) ipset (pid: 3591715) (username: rafaeldtinoco - uid: 1000) - CREATE test123 (type: hash:ip)
(2021/03/12_17:33) ipset (pid: 3591719) (username: rafaeldtinoco - uid: 1000) - CREATE test456 (type: hash:ip)
(2021/03/12_17:33) ipset (pid: 3591723) (username: rafaeldtinoco - uid: 1000) - CREATE test789 (type: hash:ip)
```

```
$ sudo ipset create test123 hash:ip
...
```

> Note that -v option will give you important debug information (verbose) of libbpf internals. It is important to understand all work libbpf does under the hood when loading the binary, rellocating all eBPF bytecode symbols using BTF information caught either from sysfs (recent kernels) or a .BPF section of an ELF file (older kernels).

## Portable libbpf based ebpf code: Older Kernels

And, to prove it works in an older version as well - as long as you apply the **link-vmlinux.sh.patch** and rebuild it - you can build an older v4.15.x kernel like:

```
[rafaeldtinoco@bioniccontainer ibm-gt]$ git clone git://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/bionic

[rafaeldtinoco@bioniccontainer ibm-gt]$ cp debian/scripts/retpoline-extract-one scripts/ubuntu-retpoline-extract-one

[rafaeldtinoco@bioniccontainer bionic]$ patch -p1 < ~/devel/portablebpf/patches/link-vmlinux.sh.patch
patching file scripts/link-vmlinux.sh

[rafaeldtinoco@bioniccontainer bionic]$ cp /boot/config-xxxxxx .config

[rafaeldtinoco@bioniccontainer bionic]$ make olddefconfig
  HOSTCC  scripts/basic/fixdep
  HOSTCC  scripts/basic/bin2c
  HOSTCC  scripts/kconfig/conf.o
  HOSTCC  scripts/kconfig/zconf.tab.o
  HOSTLD  scripts/kconfig/conf
scripts/kconfig/conf  --olddefconfig Kconfig
security/Kconfig:386:warning: defaults for choice values not supported
security/Kconfig:390:warning: defaults for choice values not supported
security/Kconfig:394:warning: defaults for choice values not supported
security/Kconfig:398:warning: defaults for choice values not supported
security/Kconfig:402:warning: defaults for choice values not supported
#
# configuration written to .config
#

[rafaeldtinoco@bioniccontainer bionic]$ make -j20 deb-pkg

TO BE FINISHED
```
