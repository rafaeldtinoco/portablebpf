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

#include "mine.h"
#include "mine.skel.h"

int daemonize = 0;
static int bpfverbose = 0;
static volatile bool exiting;

#define __NR_perf_event_open 298

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100

// GENERAL

char *get_currtime(void)
{
	char *datetime = malloc(100);
	time_t t = time(NULL);
	struct tm *tmp;

	memset(datetime, 0, 100);

	if ((tmp = localtime(&t)) == NULL)
		EXITERR("could not get localtime");

	if ((strftime(datetime, 100, "%Y/%m/%d_%H:%M", tmp)) == 0)
		EXITERR("could not parse localtime");

	return datetime;
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

char *get_username(uint32_t uid)
{
	char *username = malloc(100);
	struct passwd *p = getpwuid(uid);

	memset(username, 0, 100);
	if (p && p->pw_name)
		strncpy(username, p->pw_name, 99);

	return username;
}

// LOGGING RELATED

void initlog()
{
	openlog(NULL, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_USER);
}

void endlog()
{
	closelog();
}

// DAEMON RELATED

int makemeadaemon(void)
{
	int fd;

	fprintf(stdout, "Daemon mode. Check syslog for messages!\n");

	switch(fork()) {
	case -1:	return -1;
	case 0:		break;
	default:	exit(0);
	}

	if (setsid() == -1)
		return -1;

	switch(fork()) {
	case -1:	return -1;
	case 0:		break;
	default:	exit(0);
	}

	umask(022);

	if (chdir("/") == -1)
		return -1;

	close(0); close(1); close(2);

	fd = open("/dev/null", O_RDWR);

	if (fd != 0)
		return -1;
	if (dup2(0, 1) != 1)
		return -1;
	if (dup2(0, 2) != 2)
		return -1;

	return 0;
}

int dontmakemeadaemon(void)
{
	fprintf(stdout, "Foreground mode...<Ctrl-C> or or SIG_TERM to end it.\n");

	umask(022);

	return 0;
}

// OUTPUT

static int output(struct data_t *e)
{
	char *username, *currtime = get_currtime();

	if ((username = get_username(e->loginuid)) == NULL)
		username = "null";

	OUTPUT("(%s) %s (pid: %d) (username: %s - uid: %d)\n",
               currtime, e->comm, e->pid, username, e->loginuid);

	if (username != NULL)
		free(username);

	free(currtime);

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !bpfverbose)
		return 0;

	return vfprintf(stderr, format, args);
}

// USAGE

int usage(int argc, char **argv)
{
	fprintf(stdout,
		"\n"
		"Syntax: %s [options]\n"
		"\n"
		"\t[options]:\n"
		"\n"
		"\t-v: bpf verbose mode\n"
		"\t-d: daemon mode (output to syslog)\n"
		"\n"
		"Check https://rafaeldtinoco.github.io/portablebpf/ for more info!\n"
		"\n",
		argv[0]);

	exit(0);
}

// PERF EVENTS

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

// EBPF USERLAND PORTION

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
		case 'd':
			daemonize = 1;
			break;
		case 'h':
		default:
			usage(argc, argv);
		}
	}

	daemonize ? err = makemeadaemon() : dontmakemeadaemon();
	if (err == -1)
		EXITERR("failed to become a deamon");

	signal(SIGINT, trap);
	signal(SIGTERM, trap);

	if (daemonize)
		initlog();

	libbpf_set_print(libbpf_print_fn);

	if ((err = bump_memlock_rlimit()))
		EXITERR("failed to increase rlimit: %d", err);

	if (!(mine = mine_bpf__open()))
		EXITERR("failed to open BPF object");

	if ((pid_max = get_pid_max()) < 0)
		EXITERR("failed to get pid_max");

	if (kern_version) {
		if (sscanf(kern_version, "%u.%u.%u", &major, &minor, &patch) != 3)
			WARN("could not parse env variable kern_version");

		full = KERNEL_VERSION(major, minor, patch);

		if (bpf_object__set_kversion(mine->obj, full) < 0)
			EXITERR("could not set kern_version attribute");
	}

	if ((err = mine_bpf__load(mine)))
		CLEANERR("failed to load BPF object: %d\n", err);

	if ((err = mine_bpf__attach(mine)))
		CLEANERR("failed to attach\n");

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;

	pb = perf_buffer__new(bpf_map__fd(mine->maps.events), PERF_BUFFER_PAGES, &pb_opts);

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

		if (exiting)
			break;
	}

cleanup:
	if (daemonize)
		endlog();

	perf_buffer__free(pb);
	mine_bpf__destroy(mine);

	return err != 0;
}
