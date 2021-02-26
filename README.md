# Creating a portable eBPF binary using statlic libbpf

I have made this "hello-world" type of eBPF application using a static libbpf approach.
This example will do a single printf() per **SYNC** syscall executed. 
**Important part here** is not the eBPF part, very simple, but the way everything is being built,
so the binary can be portable and executed in different kernels.

> This came from bpfcc/libbpf-tools AND 
[BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html) + 
[HOWTO: BCC to libbpf conversion](https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html) 

#### You can clone this and create your own portable eBPF application using this as a base point, instead of relying on BPFCC and having your eBPF bytecode compiled runtime each time you run the app.

## Output Example

```
$ sudo ./mine 
libbpf: loading object 'mine_bpf' from buffer
libbpf: elf: section(2) kprobe/ksys_sync, size 328, link 0, flags 6, type=1
libbpf: sec 'kprobe/ksys_sync': found program 'ksys_sync' at insn offset 0 (0 bytes), code size 41 insns (328 bytes)
libbpf: elf: section(3) license, size 4, link 0, flags 3, type=1
libbpf: license of mine_bpf is GPL
libbpf: elf: section(4) .maps, size 48, link 0, flags 3, type=1
libbpf: elf: section(5) .bss, size 16, link 0, flags 3, type=8
libbpf: elf: section(6) .BTF, size 25959, link 0, flags 0, type=1
libbpf: elf: section(7) .BTF.ext, size 348, link 0, flags 0, type=1
libbpf: elf: section(8) .symtab, size 216, link 13, flags 0, type=2
libbpf: elf: section(9) .relkprobe/ksys_sync, size 80, link 8, flags 0, type=9
libbpf: looking for externs among 9 symbols...
libbpf: collected 0 externs total
libbpf: map 'start': at sec_idx 4, offset 0.
libbpf: map 'start': found type = 1.
libbpf: map 'start': found key [6], sz = 4.
libbpf: map 'start': found value [10], sz = 8.
libbpf: map 'hists': at sec_idx 4, offset 24.
libbpf: map 'hists': found type = 1.
libbpf: map 'hists': found key [6], sz = 4.
libbpf: map 'hists': found value [16], sz = 16.
libbpf: map 'mine_bpf.bss' (global data): at sec_idx 5, offset 0, flags 400.
libbpf: map 2 is "mine_bpf.bss"
libbpf: sec '.relkprobe/ksys_sync': collecting relocation for section(2) 'kprobe/ksys_sync'
libbpf: sec '.relkprobe/ksys_sync': relo #0: insn #9 against 'start'
libbpf: prog 'ksys_sync': found map 0 (start, sec 4, off 0) for insn #9
libbpf: sec '.relkprobe/ksys_sync': relo #1: insn #15 against 'hists'
libbpf: prog 'ksys_sync': found map 1 (hists, sec 4, off 24) for insn #15
libbpf: sec '.relkprobe/ksys_sync': relo #2: insn #21 against 'hists'
libbpf: prog 'ksys_sync': found map 1 (hists, sec 4, off 24) for insn #21
libbpf: sec '.relkprobe/ksys_sync': relo #3: insn #24 against '.bss'
libbpf: prog 'ksys_sync': found data map 2 (mine_bpf.bss, sec 5, off 0) for insn 24
libbpf: sec '.relkprobe/ksys_sync': relo #4: insn #28 against 'hists'
libbpf: prog 'ksys_sync': found map 1 (hists, sec 4, off 24) for insn #28
libbpf: loading kernel BTF '/sys/kernel/btf/vmlinux': 0
libbpf: map 'start': created successfully, fd=4
libbpf: map 'hists': created successfully, fd=5
libbpf: map 'mine_bpf.bss': created successfully, fd=6
libbpf: sec 'kprobe/ksys_sync': found 1 CO-RE relocations
libbpf: prog 'ksys_sync': relo #0: kind <byte_off> (0), spec is [26] struct task_struct.comm (0:103 @ offset 2712)
libbpf: CO-RE relocating [0] struct task_struct: found target candidate [116] struct task_struct in [vmlinux]
libbpf: prog 'ksys_sync': relo #0: matching candidate #0 [116] struct task_struct.comm (0:103 @ offset 2712)
libbpf: prog 'ksys_sync': relo #0: patched insn #33 (ALU/ALU64) imm 2712 -> 2712
Tracing syscall "sync"... Hit Ctrl-C to end.
tid = 653984 sync
tid = 653987 sync
```
