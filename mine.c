#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "mine.h"
#include "mine.skel.h"

#define __NR_perf_event_open 298

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

static volatile bool exiting;

// LEGACY KPROBE ATTACH (COULD BE PART OF LIBBPF BUT IT IS NOT)
// (thanks to Andrii Nakryiko idea explaining libbpf did not support legacy probe)

int
poke_kprobe_events(bool add, const char* name, bool ret)
{
	char buf[256];
	int fd, err;

	fd = open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND, 0);
	if (fd < 0) {
		err = -errno;
		fprintf(stderr, "failed to open kprobe_events file: %d\n", err);
		return err;
	}

	if (add)
		snprintf(buf, sizeof(buf), "%c:kprobes/%s %s", ret ? 'r' : 'p', name, name);
	else
		snprintf(buf, sizeof(buf), "-:kprobes/%s", name);

	err = write(fd, buf, strlen(buf));
	if (err < 0) {
		err = -errno;
		fprintf(stderr, "failed to %s kprobe '%s': %d\n", add ? "add" : "remove", buf, err);
	}
	close(fd);

	return err >= 0 ? 0 : err;
}

int
add_kprobe_event(const char* func_name, bool is_kretprobe)
{
	return poke_kprobe_events(true /*add*/, func_name, is_kretprobe);
}

int
remove_kprobe_event(const char* func_name, bool is_kretprobe)
{
	return poke_kprobe_events(false /*remove*/, func_name, is_kretprobe);
}

struct bpf_link *
attach_kprobe_legacy(struct bpf_program* prog, const char* func_name, bool is_kretprobe)
{
	char fname[256];
	struct perf_event_attr attr;
	struct bpf_link* link;
	int fd = -1, err, id;
	FILE* f = NULL;

	err = add_kprobe_event(func_name, is_kretprobe);
	if (err) {
		fprintf(stderr, "failed to create kprobe event: %d\n", err);
		return NULL;
	}

	snprintf(fname, sizeof(fname), "/sys/kernel/debug/tracing/events/kprobes/%s/id", func_name);
	f = fopen(fname, "r");
	if (!f) {
		fprintf(stderr, "failed to open kprobe id file '%s': %d\n", fname, -errno);
		goto err_out;
	}

	if (fscanf(f, "%d\n", &id) != 1) {
		fprintf(stderr, "failed to read kprobe id from '%s': %d\n", fname, -errno);
		goto err_out;
	}

	fclose(f);
	f = NULL;

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.config = id;
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "failed to create perf event for kprobe ID %d: %d\n", id, -errno);
		goto err_out;
	}

	link = bpf_program__attach_perf_event(prog, fd);
	err = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "failed to attach to perf event FD %d: %d\n", fd, err);
		goto err_out;
	}

	return link;

	err_out:
	if (f)
		fclose(f);
	if (fd >= 0)
		close(fd);

	remove_kprobe_event(func_name, is_kretprobe);
	return NULL;
}

// GENERAL FUNCTIONS

static int get_pid_max(void)
{
	FILE *f;
	int pid_max = 0;

	if ((f = fopen("/proc/sys/kernel/pid_max", "r")) < 0)
		RETERR("failed to open proc_sys pid_max");

	if (fscanf(f, "%d\n", &pid_max) != 1)
		RETERR("failed to read proc_sys pid_max");

	fclose(f);

	return pid_max;
}

int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

// HANDLE PERF EVENTS

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s command: %-16s (pid = %-6d)", ts, e->task, e->pid);
	printf("\n");

	return;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

// MAIN

int main(int argc, char **argv)
{
	struct mine_bpf *obj;
	int err, pid_max;
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	if ((err = bump_memlock_rlimit()))
		EXITERR("failed to increase rlimit: %d\n", err);

	if (!(obj = mine_bpf__open()))
		EXITERR("failed to open BPF object\n");

	if ((pid_max = get_pid_max()) < 0)
		EXITERR("failed to get pid_max\n");

	if ((err = mine_bpf__load(obj)))
		CLEANERR("failed to load BPF object: %d\n", err);

	obj->links.tcp_connect = attach_kprobe_legacy(obj->progs.tcp_connect, "tcp_connect", false);

	if (!obj->links.tcp_connect) {
		WARN("kprobe attach using legacy debugfs API failed, trying perf attach...");

		if ((err = mine_bpf__attach(obj)))
			CLEANERR("failed to attach BPF programs\n");
	}

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, &pb_opts);

	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("Tracing... Hit Ctrl-C to end.\n");

	while (1) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;
	}

	printf("error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	mine_bpf__destroy(obj);

	return err != 0;
}
