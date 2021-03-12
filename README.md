# Auditing ipset calls: a portable eBPF based userland daemon

Unfortunately [audit](https://github.com/linux-audit/audit-documentation/wiki) is not capable of logging
[IPset](https://en.wikipedia.org/wiki/Netfilter#ipset) calls, as those are managed by a
[netlink](https://en.wikipedia.org/wiki/Netlink) socket. **IPsetAudit** allows you to log (and audit)
IPset creation/deletion/modifications by probing kernel internal netlink handlers and passing information
to its userland daemon.

> Note: This code is being activelly developed and will change until its final release.

## Output examples

### help

``` $ sudo ./ipsetaudit -h
Syntax: ./ipsetaudit [options]

        [options]:

        -v: bpf verbose mode
        -d: daemon mode (output to syslog)

Check https://rafaeldtinoco.github.io/ipsetaudit/ for more info!
```

### foreground

```
$ sudo ./ipsetaudit
Foreground mode...<Ctrl-C> or or SIG_TERM to end it.
(2021/02/28_18:06) ipset (pid: 3771454) - TEST test123
(2021/02/28_18:06) ipset (pid: 3771457) - SAVE/LIST test456 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771453) - SAVE/LIST  - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771460) - DESTROY test789 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771458) - DESTROY test123 - ERROR
(2021/02/28_18:06) ipset (pid: 3771455) - RENAME test123 -> test456 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771452) - CREATE test789 (type: hash:ip) - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771456) - SWAP test456 <-> test789 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771459) - DESTROY test456 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771451) - CREATE test123 (type: hash:ip) - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771538) - RENAME test123 -> test456 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771540) - SAVE/LIST test456 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771542) - DESTROY test456 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771539) - SWAP test456 <-> test789 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771543) - DESTROY test789 - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771541) - DESTROY test123 - ERROR
(2021/02/28_18:06) ipset (pid: 3771536) - SAVE/LIST  - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771535) - CREATE test789 (type: hash:ip) - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771534) - CREATE test123 (type: hash:ip) - SUCCESS
(2021/02/28_18:06) ipset (pid: 3771537) - TEST test123
```

### daemon

```
$ sudo ./ipsetaudit -d
Daemon mode. Check syslog for messages!

$ journalctl -f
-- Logs begin at Wed 2020-10-21 01:16:33 -03. --
Feb 28 18:05:01 fujitsu CRON[3769761]: pam_unix(cron:session): session closed for user root
Feb 28 18:06:48 fujitsu ipsetaudit[3771649]: (2021/02/28_18:06) ipset (pid: 3771945) - DESTROY test123 - ERROR
Feb 28 18:06:48 fujitsu ipsetaudit[3771649]: (2021/02/28_18:06) ipset (pid: 3771941) - TEST test123
Feb 28 18:06:48 fujitsu ipsetaudit[3771649]: (2021/02/28_18:06) ipset (pid: 3771942) - RENAME test123 -> test456 - SUCCESS
Feb 28 18:06:48 fujitsu ipsetaudit[3771649]: (2021/02/28_18:06) ipset (pid: 3771938) - CREATE test123 (type: hash:ip) - SUCCESS
Feb 28 18:06:48 fujitsu ipsetaudit[3771649]: (2021/02/28_18:06) ipset (pid: 3771944) - SAVE/LIST test456 - SUCCESS
Feb 28 18:06:48 fujitsu ipsetaudit[3771649]: (2021/02/28_18:06) ipset (pid: 3771943) - SWAP test456 <-> test789 - SUCCESS
Feb 28 18:06:48 fujitsu ipsetaudit[3771649]: (2021/02/28_18:06) ipset (pid: 3771939) - CREATE test789 (type: hash:ip) - SUCCESS
Feb 28 18:06:48 fujitsu ipsetaudit[3771649]: (2021/02/28_18:06) ipset (pid: 3771940) - SAVE/LIST  - SUCCESS
```

### libbpf debug/verbose

```
$ sudo ./ipsetaudit -v
Foreground mode...<Ctrl-C> or or SIG_TERM to end it.
libbpf: loading object 'ipsetaudit_bpf' from buffer
libbpf: elf: section(2) kprobe/ip_set_create, size 664, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_create': found program 'ip_set_create' at insn offset 0 (0 bytes), code size 83 insns (664 bytes)
libbpf: elf: section(3) kprobe/ip_set_destroy, size 664, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_destroy': found program 'ip_set_destroy' at insn offset 0 (0 bytes), code size 83 insns (664 bytes)
libbpf: elf: section(4) kprobe/ip_set_flush, size 664, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_flush': found program 'ip_set_flush' at insn offset 0 (0 bytes), code size 83 insns (664 bytes)
libbpf: elf: section(5) kprobe/ip_set_rename, size 664, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_rename': found program 'ip_set_rename' at insn offset 0 (0 bytes), code size 83 insns (664 bytes)
libbpf: elf: section(6) kprobe/ip_set_swap, size 664, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_swap': found program 'ip_set_swap' at insn offset 0 (0 bytes), code size 83 insns (664 bytes)
libbpf: elf: section(7) kprobe/ip_set_dump, size 664, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_dump': found program 'ip_set_dump' at insn offset 0 (0 bytes), code size 83 insns (664 bytes)
libbpf: elf: section(8) kprobe/ip_set_utest, size 664, link 0, flags 6, type=1
libbpf: sec 'kprobe/ip_set_utest': found program 'ip_set_utest' at insn offset 0 (0 bytes), code size 83 insns (664 bytes)
libbpf: elf: section(9) kprobe/ip_set_uadd, size 664, link 0, flags 6, type=1
...
```

