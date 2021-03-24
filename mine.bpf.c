#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "mine.h"

// bpf map

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

// netlink packet helper

static __always_inline void *nla_data(struct nlattr *nla)
{
	return (char *) nla + NLA_HDRLEN;
}

// wrappers to make BCC and LIBBPF code to coexist (read: https://tinyl.io/3hFM)

static __always_inline long
wrap_probe_read(void *dst, size_t sz, void *src)
{
	return bpf_probe_read_kernel(dst, sz, src);
}

static __always_inline long
wrap_probe_read_str(void *dst, size_t sz, void *src)
{
	return bpf_probe_read_kernel_str(dst, sz, src);
}

// static function called by probe function

static __always_inline int
probe_enter(enum ev_type etype, void *ctx, struct nlmsghdr *nlh, struct nlattr *attr[])
{
	struct task_struct *task = (void *) bpf_get_current_task();

	// usually used for all probes

	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;
	u64 id2 = bpf_get_current_uid_gid();
	u32 gid = id2 >> 32, uid = id2;
	u64 ts = bpf_ktime_get_ns();

	struct data_t data = {};

	// populate data to be sent to userland

	data.pid = tgid;
	data.uid = uid;
	data.uid = gid;
	data.etype = etype;

	// get uid from terminal session (and not from current task)

	bpf_probe_read_kernel(&data.loginuid, sizeof(unsigned int), &task->loginuid.val);

	// get command name from task struct

	wrap_probe_read_str(&data.comm, TASK_COMM_LEN, task->comm);

	// netlink packet parsing: discover ipset name and type

	struct nlattr *nla_name, *nla_name2, *nla_type;
	wrap_probe_read(&nla_name, sizeof(void *), &attr[IPSET_ATTR_SETNAME]);
	wrap_probe_read_str(&data.ipset_name, IPSET_MAXNAMELEN, nla_data(nla_name));

	switch (data.etype) {
	case EXCHANGE_CREATE:
		wrap_probe_read(&nla_type, sizeof(void *), &attr[IPSET_ATTR_TYPENAME]);
		wrap_probe_read_str(&data.ipset_type, IPSET_MAXNAMELEN, nla_data(nla_type));
		break;
	default:
		break;
		;;
	}

	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
}

static __always_inline int
probe_return(enum ev_type etype, void *ctx, int ret)
{
	// example only

	u64 id1 = bpf_get_current_pid_tgid();
	u32 tgid = id1 >> 32, pid = id1;

	switch (etype) {
	case EXCHANGE_CREATE:
		return 0;
	default:
		break;
	}

	return 1;
}

SEC("kprobe/ip_set_create")
int BPF_KPROBE(ip_set_create, struct net *net, struct sock *ctnl, struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr *attr[])
{
	return probe_enter(EXCHANGE_CREATE, ctx, nlh, attr);
}

SEC("kretprobe/ip_set_create")
int BPF_KRETPROBE(ip_set_create_ret, int ret)
{
	return probe_return(EXCHANGE_CREATE, ctx, ret);
}

char LICENSE[] SEC("license") = "GPL";
