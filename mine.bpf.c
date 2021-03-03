#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "mine.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect)
{
	struct task_struct *this = (void *) bpf_get_current_task();

	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;

	struct event event = {};

	event.pid = tgid;
	bpf_get_current_comm(&event.task, TASK_COMM_LEN);
	bpf_perf_event_output(ctx, &events, 0xffffffffULL, &event, sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
