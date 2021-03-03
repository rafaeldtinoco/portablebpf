#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "mine.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct hist);
} hists SEC(".maps");

//static struct hist initial_hist;

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect)
{
	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;

	struct task_struct *this = (void *) bpf_get_current_task();
	struct hist *histp, *histc;

	histp = bpf_map_lookup_elem(&hists, &tgid);

	/*
	if (!histp) {
		bpf_map_update_elem(&hists, &tgid, &histc, 0);
	}
	*/

	/*
		histp = bpf_map_lookup_elem(&hists, &tgid);
		if (!histp)
			return 0;
		bpf_probe_read_kernel_str(&histp->comm, TASK_COMM_LEN, this->comm);
	}
	*/

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
