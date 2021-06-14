#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "mine.h"
#include "mine.skel.h"

static int bpfverbose = 0;
static volatile bool exiting;

char *get_currtime(void)
{
	char *datetime = malloc(100);
	time_t t = time(NULL);
	struct tm *tmp;

	memset(datetime, 0, 100);

	if ((tmp = localtime(&t)) == NULL)
		exiterr("could not get localtime");

	if ((strftime(datetime, 100, "%Y/%m/%d_%H:%M", tmp)) == 0)
		exiterr("could not parse localtime");

	return datetime;
}

static int get_pid_max(void)
{
	FILE *f;
	int pid_max = 0;

	if ((f = fopen("/proc/sys/kernel/pid_max", "r")) == NULL)
		exiterr("failed to open proc_sys pid_max");

	if (fscanf(f, "%d\n", &pid_max) != 1)
		exiterr("failed to read proc_sys pid_max");

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

char *get_username(uint32_t uid)
{
	char *username = malloc(100);
	struct passwd *p = getpwuid(uid);

	memset(username, 0, 100);
	if (p && p->pw_name)
		strncpy(username, p->pw_name, 99);

	return username;
}

char *ipv4_str(struct in_addr *addr)
{
	char temp[INET_ADDRSTRLEN];

	memset(temp, 0, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, addr, temp, INET_ADDRSTRLEN);

	return (char *) strdup(temp);
}

char *ipv6_str(struct in6_addr *addr)
{
	char temp[INET6_ADDRSTRLEN];

	memset(temp, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, addr, temp, INET6_ADDRSTRLEN);

	return (char *) strdup(temp);
}

static int output(struct data_t *e)
{
	struct in_addr src, dst;
	u16 sport = htons(e->sport);
	u16 dport = htons(e->dport);
	char *username;
	char *src_str = NULL, *dst_str = NULL;
	char *currtime = get_currtime();

	src.s_addr = e->saddr;
	dst.s_addr = e->daddr;

	username = (e->loginuid != -1) ? get_username(e->loginuid) : get_username(e->uid);

	switch (e->family) {
	case AF_INET:
		src_str = ipv4_str(&src);
		dst_str = ipv4_str(&dst);
		break;
	case AF_INET6:
		src_str = ipv6_str(&e->saddr6);
		dst_str = ipv6_str(&e->daddr6);
		break;
	}

	wrapout("(%s) %s (pid: %u) (loginuid: %u) | (%u) %s (%u) => %s (%u)",
			currtime, e->comm, e->pid, e->loginuid, (u8) e->proto,
			src_str, sport, dst_str, dport);

	if (username)
		free(username);
	free(src_str);
	free(dst_str);
	free(currtime);

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !bpfverbose)
		return 0;

	return vfprintf(stderr, format, args);
}

int usage(int argc, char **argv)
{
	fprintf(stdout,
		"\n"
		"Syntax: %s [options]\n"
		"\n"
		"\t[options]:\n"
		"\n"
		"\t-v: bpf verbose mode\n"
		"\n"
		"Check https://rafaeldtinoco.github.io/portablebpf/\n"
		"\n",
		argv[0]);

	exit(0);
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct data_t *e = data;

	output(e);

	return;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

void trap(int what)
{
	exiting = 1;
}

int main(int argc, char **argv)
{
	__u32 full, major, minor, patch;
	char *kern_version = getenv("LIBBPF_KERN_VERSION");
	int opt, err = 0, pid_max;
	struct mine_bpf *mine;
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;

	while ((opt = getopt(argc, argv, "hvd")) != -1) {
		switch(opt) {
		case 'v':
			bpfverbose = 1;
			break;
		case 'h':
		default:
			usage(argc, argv);
		}
	}

	fprintf(stdout, "Foreground mode...<Ctrl-C> or or SIG_TERM to end it.\n");

	signal(SIGINT, trap);
	signal(SIGTERM, trap);

	umask(022);

	libbpf_set_print(libbpf_print_fn);

	if ((err = bump_memlock_rlimit()))
		exiterr("failed to increase rlimit: %d", err);

	if (!(mine = mine_bpf__open()))
		exiterr("failed to open BPF object");

	if ((pid_max = get_pid_max()) < 0)
		exiterr("failed to get pid_max");

	if (kern_version) {
		if (sscanf(kern_version, "%u.%u.%u", &major, &minor, &patch) != 3)
			wrapout("could not parse env variable kern_version");
	} else {
		// If no env variable given, assume Ubuntu Bionic kernel (4.15.0)
		// and set needed version to libbpf runtime: this will guarantee
		// that the eBPF bytecode can be loaded in kernels checking
		// eBPF version attribute.
		major = (u32) 4;
		minor = (u32) 15;
		patch = (u32) 18;
	}

	full = KERNEL_VERSION(major, minor, patch);

	if (bpf_object__set_kversion(mine->obj, full) < 0)
		exiterr("could not set kern_version attribute");

	if ((err = mine_bpf__load(mine)))
		exiterr("failed to load BPF object: %d\n", err);

	if ((err = mine_bpf__attach(mine)))
		exiterr("failed to attach\n");

	/*
	 * we are not pinning anything, but could =)
	 *
	if ((err = bpf_object__pin(mine->obj, "/sys/fs/bpf/")))
		exiterr("failed to pin\n");

	if ((err = bpf_object__pin_programs(mine->obj, "/sys/fs/bpf/")))
		exiterr("failed to pin\n");
	*/

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;

	pb = perf_buffer__new(bpf_map__fd(mine->maps.events), 16 /* BUFFER PAGES */, &pb_opts);

	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	printf("Tracing... Hit Ctrl-C to end.\n");

	while (1) {
		if ((err = perf_buffer__poll(pb, 100)) < 0)
			break;

		if (exiting)
			break;
	}

cleanup:
	perf_buffer__free(pb);
	mine_bpf__destroy(mine);

	return err != 0;
}
