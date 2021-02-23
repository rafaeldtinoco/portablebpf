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
	struct hist hist;
	int err;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key))
	{
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0)
		{
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return -1;
		}

		printf("tid = %d %s\n", next_key, hist.comm);

		lookup_key = next_key;
	}

	lookup_key = -2;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key))
	{
		err = bpf_map_delete_elem(fd, &next_key);
		if (err < 0)
		{
			fprintf(stderr, "failed to cleanup hist : %d\n", err);
			return -1;
		}

		lookup_key = next_key;
	}

	return 0;
}

static int get_pid_max(void)
{
	int pid_max;
	FILE *f;

	f = fopen("/proc/sys/kernel/pid_max", "r");
	if (!f)
		return -1;

	if (fscanf(f, "%d\n", &pid_max) != 1)
		pid_max = -1;

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

	err = bump_memlock_rlimit();
	if (err)
	{
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = mine_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "failed to open BPF object\n");
		return 1;
	}

	pid_max = get_pid_max();
	if (pid_max < 0)
	{
		fprintf(stderr, "failed to get pid_max\n");
		return 1;
	}

	bpf_map__resize(obj->maps.start, pid_max);
	bpf_map__resize(obj->maps.hists, pid_max);

	err = mine_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = mine_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	fd = bpf_map__fd(obj->maps.hists);

	signal(SIGINT, sig_handler);

	printf("Tracing syscall \"sync\"... Hit Ctrl-C to end.\n");

	/* main: poll */
	while (1)
	{
		sleep(5); // 5 sec interval

		err = print_hists(fd);
		if (err)
			break;

		if (exiting)
			break;
	}

cleanup:
	mine_bpf__destroy(obj);

	return err != 0;
}
