#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
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

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "hijack.h"
#include "hijack.skel.h"

#include <asm/unistd.h>

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

int main(int argc, char **argv)
{
	int fd;
	union bpf_attr prog_attr, map_attr;
	struct bpf_prog_info prog_info = {};
	struct bpf_map_info map_info = {};

	// PINNED PROGRAM EXAMPLE: KPROBE_KSYS_SYNC

	memset(&prog_attr, 0, sizeof(prog_attr));

	prog_attr.pathname = (__u64) (unsigned long) strdup("/sys/fs/bpf/kprobe_ksys_sync");

	// get program file descriptor
	fd = sys_bpf(BPF_OBJ_GET, &prog_attr, sizeof(prog_attr));
	if (fd < 0)
		EXITERR("could not get fd\n");

	// buffer for prog info
	prog_attr.info.bpf_fd = fd;
	prog_attr.info.info_len = sizeof(prog_info);
	prog_attr.info.info = (__u64) (unsigned long) &prog_info;

	// get program info
	fd = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, (union bpf_attr *) &prog_attr, sizeof(prog_attr));
	if (fd < 0)
		EXITERR("could not get info\n");

	// PINNED MAP EXAMPLE: EVENTS

	memset(&map_attr, 0, sizeof(map_attr));

	map_attr.pathname = (__u64) (unsigned long) strdup("/sys/fs/bpf/events");

	// get map file descriptor
	fd = sys_bpf(BPF_OBJ_GET, &map_attr, sizeof(map_attr));
	if (fd < 0)
		EXITERR("could not get fd\n");

	// buffer for map info
	memset(&map_attr, 0, sizeof(map_attr));
	map_attr.info.bpf_fd = fd;
	map_attr.info.info_len = sizeof(map_info);
	map_attr.info.info = (__u64) (unsigned long) &map_info;

	fd = sys_bpf(BPF_OBJ_GET_INFO_BY_FD, (union bpf_attr *) &map_attr, sizeof(map_attr));
	if (fd < 0)
		EXITERR("could not get info\n");

	return 0;
}
