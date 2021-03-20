#ifndef MINE_H_
#define MINE_H_

#ifdef NOTBCC

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

#else

// BCC ONLY

#include <uapi/linux/ptrace.h>
#include <net/sock.h>

BPF_PERF_OUTPUT(events);

#endif

// COMMON TO BCC AND LIBBPF

typedef unsigned int u32;

#define TASK_COMM_LEN 16
#define IPSET_MAXNAMELEN 32

extern int daemonize;

enum ev_type {
	EXCHANGE_CREATE = 1,
	EXCHANGE_DESTROY = 2,
	EXCHANGE_FLUSH = 3,
	EXCHANGE_RENAME = 4,
	EXCHANGE_SWAP = 5,
	EXCHANGE_DUMP = 6,
	EXCHANGE_TEST = 7,
	EXCHANGE_ADD = 8,
	EXCHANGE_DEL = 9,
};

struct data_t {
	u32 pid;
	u32 uid;
	u32 gid;
	u32 loginuid;
	u32 ret;
	enum ev_type etype;
	char comm[TASK_COMM_LEN];
	char ipset_name[IPSET_MAXNAMELEN];
	char ipset_newname[IPSET_MAXNAMELEN];
	char ipset_type[IPSET_MAXNAMELEN];
};

// IPSET RELATED

typedef __u16 ip_set_id_t;

struct ip_set_net {
	struct ip_set  *ip_set_list;
	ip_set_id_t	ip_set_max;
	bool		is_deleted;
	bool		is_destroyed;
};

enum {
	IPSET_ATTR_UNSPEC,
	IPSET_ATTR_PROTOCOL,
	IPSET_ATTR_SETNAME,
	IPSET_ATTR_TYPENAME,
	IPSET_ATTR_SETNAME2 = IPSET_ATTR_TYPENAME,
	IPSET_ATTR_REVISION,
	IPSET_ATTR_FAMILY,
	IPSET_ATTR_FLAGS,
	IPSET_ATTR_DATA,
	IPSET_ATTR_ADT,
	IPSET_ATTR_LINENO,
	IPSET_ATTR_PROTOCOL_MIN,
	IPSET_ATTR_REVISION_MIN	= IPSET_ATTR_PROTOCOL_MIN,
	IPSET_ATTR_INDEX,
	__IPSET_ATTR_CMD_MAX,
};
#define IPSET_ATTR_CMD_MAX (__IPSET_ATTR_CMD_MAX - 1)

// NETLINK RELATED

#define NLA_ALIGNTO		4
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN		((int) NLA_ALIGN(sizeof(struct nlattr)))

#endif // MINE_H_
