#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "mine.h"
#include "mine.skel.h"

static volatile bool exiting;

static int print_hists(int fd)
{
	__u32 lookup_key = -2, next_key;
	struct hist c;
	int err;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {

		if((err = bpf_map_lookup_elem(fd, &next_key, &c)) < 0)
			EXITERR("failed to lookup created: %d\n", err);

		printf("command: %s (pid = %d) sync'ed\n", c.comm, next_key);

		lookup_key = next_key;
	}

	lookup_key = -2;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {

		if((err = bpf_map_delete_elem(fd, &next_key)) < 0)
			EXITERR("failed to cleanup created: %d\n", err);

		lookup_key = next_key;
	}

	return 0;
}

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

static void sig_handler(int sig)
{
	exiting = true;
}

int main(int argc, char **argv)
{
	struct mine_bpf *obj;
	int err, pid_max, fd;

	libbpf_set_print(libbpf_print_fn);

	if ((err = bump_memlock_rlimit()))
		EXITERR("failed to increase rlimit: %d\n", err);

	if (!(obj = mine_bpf__open()))
		EXITERR("failed to open BPF object\n");

	if ((pid_max = get_pid_max()) < 0)
		EXITERR("failed to get pid_max\n");

	bpf_map__resize(obj->maps.hists, pid_max);

	if ((err = mine_bpf__load(obj)))
		CLEANERR("failed to load BPF object: %d\n", err);

	if ((err = mine_bpf__attach(obj)))
		CLEANERR("failed to attach BPF programs\n");

	fd = bpf_map__fd(obj->maps.hists);

	signal(SIGINT, sig_handler);

	printf("Tracing syscall \"sync\"... Hit Ctrl-C to end.\n");

	while (1) {

		if ((err = print_hists(fd)))
			break;

		if (exiting)
			break;

		sleep(5);
	}

cleanup:
	mine_bpf__destroy(obj);
	return err != 0;
}
