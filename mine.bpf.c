#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "mine.h"

// BPF MAPS

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct net *net, struct sock *ctnl, struct sk_buff *skb,
		struct nlmsghdr *nlh, struct nlattr *attr[])
{
	struct task_struct *this = (void *) bpf_get_current_task();
        u64 id1 = bpf_get_current_pid_tgid();
        u32 tgid = id1 >> 32, pid = id1;
        u64 id2 = bpf_get_current_uid_gid();
        u32 gid = id2 >> 32, uid = id2;
        u64 ts = bpf_ktime_get_ns();

        // construct an event

        struct event event = {};
        event.pid = tgid;
        event.uid = uid;
        event.uid = gid;

        bpf_probe_read_kernel_str(&event.comm, TASK_COMM_LEN, this->comm);

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &event, sizeof(event));

}

char LICENSE[] SEC("license") = "GPL";
