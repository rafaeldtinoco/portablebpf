#ifdef NOTBCC
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#endif

#include "mine.h"

#ifdef NOTBCC

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
#endif

// wrappers to make BCC and LIBBPF code to coexist (read: https://tinyl.io/3hFM)

static __always_inline long
wrap_probe_read(void *dst, size_t sz, void *src)
{
#ifdef NOTBCC
	return bpf_probe_read_kernel(dst, sz, src);
#else
	return bpf_probe_read(dst, sz, src);
#endif
}

static __always_inline long
wrap_probe_read_str(void *dst, size_t sz, void *src)
{
#ifdef NOTBCC
	return bpf_probe_read_kernel_str(dst, sz, src);
#else
	return bpf_probe_read_str(dst, sz, src);
#endif
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

#ifdef NOTBCC
	bpf_probe_read_kernel(&data.loginuid, sizeof(unsigned int), &task->loginuid.val);
#else
	data.loginuid = task->loginuid.val;
#endif
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

#ifdef NOTBCC
	return bpf_perf_event_output(ctx, &events, 0xffffffffULL, &data, sizeof(data));
#else
	return events.perf_submit(ctx, &data, sizeof(data));
#endif
}

#ifdef NOTBCC
SEC("kprobe/ip_set_create")
int BPF_KPROBE(ip_set_create, struct net *net, struct sock *ctnl, struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr *attr[])
#else
int kprobe__ip_set_create(struct pt_regs *ctx, struct net *net, struct sock *ctnl, struct sk_buff *skb, struct nlmsghdr *nlh, struct nlattr **attr)
#endif
{
	return probe_enter(EXCHANGE_CREATE, ctx, nlh, attr);
}

char LICENSE[] SEC("license") = "GPL";
