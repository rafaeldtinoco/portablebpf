#ifndef MINE_H_
#define MINE_H_

// GENERAL

#define TASK_COMM_LEN 16

extern int daemonize;

struct event {
	pid_t pid;
	uint32_t uid;
	uint32_t gid;
	char comm[TASK_COMM_LEN];
};

// OUTPUT

#define HERE fprintf(stderr, "line %d, file %s, function %s\n", __LINE__, __FILE__, __func__)

#define WARN(...)			\
{					\
	fprintf(stderr, __VA_ARGS__);	\
	fprintf(stderr, "\n");		\
}

#define EXITERR(...)			\
{					\
	fprintf(stderr, __VA_ARGS__);	\
	fprintf(stderr, "\n");		\
	HERE;				\
	exit(1);			\
}

#define RETERR(...)			\
{					\
	fprintf(stderr, __VA_ARGS__);	\
	fprintf(stderr, "\n");		\
	HERE;				\
	return -1;			\
}

#define CLEANERR(...)			\
{					\
	fprintf(stderr, __VA_ARGS__);	\
	fprintf(stderr, "\n");		\
	HERE;				\
	goto cleanup;			\
}

#define OUTPUT(...)						\
{								\
	switch (daemonize) {					\
	case 0:							\
		fprintf(stdout, __VA_ARGS__);			\
		break;						\
	case 1:							\
		syslog(LOG_USER | LOG_INFO, __VA_ARGS__);	\
		break;						\
	}							\
}

#endif
