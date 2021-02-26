# Creating a portable eBPF binary using statlic libbpf

I have made this "hello-world" type of eBPF application using a static libbpf 
approach. This example will do a single printf() per **sync** syscall executed.
**Important part here** is not the eBPF code, but the way everything is being 
built, so the binary can be portable and executed in different kernels.

> This came from bpfcc/libbpf-tools AND 
[BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html) + 
[HOWTO: BCC to libbpf conversion](https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html) 

#### You can clone this and create your own eBPF application using this as a base point.
