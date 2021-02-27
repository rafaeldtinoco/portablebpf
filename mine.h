#ifndef MINE_H_
#define MINE_H_

#define TASK_COMM_LEN 16

#define HERE fprintf(stderr, "line %d, file %s, function %s\n", __LINE__, __FILE__, __func__)

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

#define TASK_COMM_LEN	16

struct hist {
	char comm[TASK_COMM_LEN];
};

#endif /* MINE_H_ */
