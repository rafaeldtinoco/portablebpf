#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "mine.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");

static struct hist initial_hist;

static __always_inline void store_start(u32 tgid, u32 pid, u64 ts)
{
	bpf_map_update_elem(&start, &tgid, &ts, 0);
}

static __always_inline void update_hist(struct task_struct *task, u32 tgid, u32 pid, u64 ts)
{
	u64 delta, *tsp, slot;
	struct hist *histp;

	tsp = bpf_map_lookup_elem(&start, &tgid);
	if (tsp)
		return;

	histp = bpf_map_lookup_elem(&hists, &tgid);

	if (!histp) {

		bpf_map_update_elem(&hists, &tgid, &initial_hist, 0);

		histp = bpf_map_lookup_elem(&hists, &tgid);
		if (!histp)
			return;

		BPF_CORE_READ_STR_INTO(&histp->comm, task, comm);
	}
}

SEC("kprobe/ksys_sync")
int BPF_KPROBE(ksys_sync)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32, pid = id;
	u64 ts = bpf_ktime_get_ns();
	struct hist *histp;

	update_hist((void*) bpf_get_current_task(), tgid, pid, ts);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
