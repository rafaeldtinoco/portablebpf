#!/usr/bin/env python

from bcc import BPF
import ctypes as ct

# GENERAL

TASK_COMM_LEN = 16
IPSET_MAXNAMELEN = 32

EXCHANGE_CREATE = 1
EXCHANGE_DESTROY = 2
EXCHANGE_FLUSH = 3
EXCHANGE_RENAME = 4
EXCHANGE_SWAP = 5
EXCHANGE_DUMP = 6
EXCHANGE_TEST = 7
EXCHANGE_ADD = 8
EXCHANGE_DEL = 9

class datastruct(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("gid", ct.c_uint),
        ("loginuid", ct.c_uint),
        ("ret", ct.c_uint),
        ("ev_type", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("ipset_name", ct.c_char * IPSET_MAXNAMELEN),
        ("ipset_newname", ct.c_char * IPSET_MAXNAMELEN),
        ("ipset_type", ct.c_char * IPSET_MAXNAMELEN)
    ]

# OUTPUT

def callback(cpu, data, size):
    assert size >= ct.sizeof(datastruct)
    event = ct.cast(data, ct.POINTER(datastruct)).contents
    if event.ev_type == EXCHANGE_CREATE:
        print("%s (pid: %d) (auid: %d) - CREATE %s (type: %s)" % (event.comm,
            event.pid, event.loginuid, event.ipset_name, event.ipset_type));

# MAIN

b = BPF(src_file="mine.bpf.c")
b["events"].open_perf_buffer(callback)

print("Tracing... Hit Ctrl-C to end.")

while 1:
    b.kprobe_poll()
