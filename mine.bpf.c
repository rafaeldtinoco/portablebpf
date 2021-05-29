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

static __always_inline int
probe_enter(void *ctx)
{
	struct task_struct *task = (void *) bpf_get_current_task();
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;
	u64 ts = bpf_ktime_get_ns();

	struct data_t data = {};
	data.pid = tgid;
	data.uid = uid;
	data.uid = gid;

	bpf_probe_read_kernel(&data.loginuid, sizeof(unsigned int), &task->loginuid.val);
	bpf_probe_read_kernel_str(&data.comm, TASK_COMM_LEN, task->comm);

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

SEC("kprobe/ksys_sync")
int BPF_KPROBE(ksys_sync)
{
	return probe_enter(ctx);
}

char LICENSE[] SEC("license") = "GPL";
