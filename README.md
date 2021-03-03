# Creating a portable eBPF binary using statlic libbpf

I have made this "hello-world" type of eBPF application using a static libbpf approach.
This example will inform the command and pid of a process doing a tcp v4 connect() call.
**Important** here is not the eBPF code, very simple, but the way this is built, making it portable.
After compilling this you are able to run the same binary (and embedded eBPF object) in different kernels.

> This came from bpfcc/libbpf-tools AND
[BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html) +
[HOWTO: BCC to libbpf conversion](https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html)

#### You can clone this and create your own portable eBPF application using this as a base point, instead of relying on BPFCC and having your eBPF bytecode compiled runtime each time you run the app.

Check [IPsetAudit](https://github.com/rafaeldtinoco/ipsetaudit) tool for an example of this being used.

## Caveats

1. In mine.c you will find a function attach\_kprobe\_legacy(). The libbpf
   library **DOES NOT support** attaching to kprobes through the **old
   mechanism** (/sys/kernel/debug/tracing/events/kprobes). As I wanted the code
   to run in old kernels as well I have added those functions.

2. If running this code in **kernels that don't support BTF** (4.x), you will
   need to [change the way kernel is compiled](https://github.com/torvalds/linux/blob/master/scripts/link-vmlinux.sh#L213)
   so your link script generates BTF ELF sections. There is a script at
   `patches/link-vmlinux.sh.patch` highlighting the changes you need.

   After having a BTF populated ELF file you can extract the vmlinux.h header
   with:<BR>
   `./bpftool btf dump file /boot/btf-4.15.18+ format c > include/4.15.0-vmlinux.h`

3. Because BPF did not support [global data](https://lwn.net/Articles/784936/)
   (variables) we have to use [perf events data stores](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
   (or some other compatible to old kernels data store). You can't simply
   bpf\_map\_update\_elem() pointing to DATA section as it does not exist for the running bytecode.

4. For older OSes, make sure to use **at least** clang-10 to compile this (Like in Ubuntu Bionic).

## Output Example

```
$ uname -a
Linux fujitsu 5.8.0-43-generic #49-Ubuntu SMP Fri Feb 5 03:01:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

$ sudo ./mine
libbpf: loading object 'mine_bpf' from buffer
libbpf: elf: section(2) kprobe/tcp_connect, size 200, link 0, flags 6, type=1
libbpf: sec 'kprobe/tcp_connect': found program 'tcp_connect' at insn offset 0 (0 bytes), code size 25 insns (200 bytes)
libbpf: elf: section(3) license, size 4, link 0, flags 3, type=1
libbpf: license of mine_bpf is GPL
libbpf: elf: section(4) .maps, size 24, link 0, flags 3, type=1
libbpf: elf: section(5) .BTF, size 1231, link 0, flags 0, type=1
libbpf: elf: section(6) .BTF.ext, size 240, link 0, flags 0, type=1
libbpf: elf: section(7) .symtab, size 144, link 12, flags 0, type=2
libbpf: elf: section(8) .relkprobe/tcp_connect, size 16, link 7, flags 0, type=9
libbpf: looking for externs among 6 symbols...
libbpf: collected 0 externs total
libbpf: map 'events': at sec_idx 4, offset 0.
libbpf: map 'events': found type = 4.
libbpf: map 'events': found key_size = 4.
libbpf: map 'events': found value_size = 4.
libbpf: sec '.relkprobe/tcp_connect': collecting relocation for section(2) 'kprobe/tcp_connect'
libbpf: sec '.relkprobe/tcp_connect': relo #0: insn #16 against 'events'
libbpf: prog 'tcp_connect': found map 0 (events, sec 4, off 0) for insn #16
libbpf: map 'events': setting size to 24
libbpf: map 'events': created successfully, fd=4
failed to add kprobe 'p:kprobes/tcp_connect tcp_connect': -17
failed to create kprobe event: -17
kprobe attach using legacy debugfs API failed, trying perf attach...
Tracing... Hit Ctrl-C to end.
13:15:09 command: Chrome_ChildIOT  (pid = 2253844)
13:15:15 command: nc               (pid = 58046 )
```

```
$ uname -a
Linux IBM 4.15.18+ #18 SMP Mon Mar 1 18:11:14 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

$ sudo ./mine
libbpf: loading object 'mine_bpf' from buffer
libbpf: elf: section(2) kprobe/tcp_connect, size 200, link 0, flags 6, type=1
libbpf: sec 'kprobe/tcp_connect': found program 'tcp_connect' at insn offset 0 (0 bytes), code size 25 insns (200 bytes)
libbpf: elf: section(3) license, size 4, link 0, flags 3, type=1
libbpf: license of mine_bpf is GPL
libbpf: elf: section(4) .maps, size 24, link 0, flags 3, type=1
libbpf: elf: section(5) .BTF, size 1231, link 0, flags 0, type=1
libbpf: elf: section(6) .BTF.ext, size 240, link 0, flags 0, type=1
libbpf: elf: section(7) .symtab, size 144, link 12, flags 0, type=2
libbpf: elf: section(8) .relkprobe/tcp_connect, size 16, link 7, flags 0, type=9
libbpf: looking for externs among 6 symbols...
libbpf: collected 0 externs total
libbpf: map 'events': at sec_idx 4, offset 0.
libbpf: map 'events': found type = 4.
libbpf: map 'events': found key_size = 4.
libbpf: map 'events': found value_size = 4.
libbpf: sec '.relkprobe/tcp_connect': collecting relocation for section(2) 'kprobe/tcp_connect'
libbpf: sec '.relkprobe/tcp_connect': relo #0: insn #16 against 'events'
libbpf: prog 'tcp_connect': found map 0 (events, sec 4, off 0) for insn #16
libbpf: Kernel doesn't support BTF, skipping uploading it.
libbpf: map 'events': setting size to 8
libbpf: map 'events': created successfully, fd=3
Tracing... Hit Ctrl-C to end.
16:14:52 command: nc               (pid = 8827  )
16:15:00 command: ssh              (pid = 8833  )
```
