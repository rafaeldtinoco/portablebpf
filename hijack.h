#ifndef HIJACK_H_
#define HIJACK_H_

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

// LIBBPF ONLY

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

typedef unsigned int u32;

#define TASK_COMM_LEN 16
#define IPSET_MAXNAMELEN 32

struct data_t {
	u32 pid;
	u32 uid;
	u32 gid;
	u32 loginuid;
	u32 ret;
	char comm[TASK_COMM_LEN];
	char ipset_name[IPSET_MAXNAMELEN];
	char ipset_newname[IPSET_MAXNAMELEN];
	char ipset_type[IPSET_MAXNAMELEN];
};

#endif // HIJACK_H_
