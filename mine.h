#ifndef MINE_H_
#define MINE_H_

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#define _wrapout(nl, ...)		\
{					\
	fprintf(stdout, __VA_ARGS__);	\
	if (nl)				\
		fprintf(stdout, "\n");	\
}

#define _wrapout0(...) _wrapout(0, __VA_ARGS__)
#define _wrapout1(...) _wrapout(1, __VA_ARGS__)

#define wrapout  _wrapout1
#define here     _wrapout1("line %d, file %s, function %s", __LINE__, __FILE__, __func__)
#define debug(a) _wrapout1("%s (line %d, file %s, function %s)", a, __LINE__, __FILE__, __func__)

#define exiterr(...)	\
{			\
	here;		\
        exit(1);	\
}

struct data_t {
        char comm[16];          // command (task_comm_len)
        u32  pid;               // proccess id
        u32  uid;               // user id
        u32  gid;               // group id
        u32  loginuid;          // real user (login/terminal)
        u8   family;            // network family
        u8   proto;             // protocol (sock.h: u8 older, u16 newer)
        u16  sport;             // source port
        u16  dport;             // destination port
        u32  saddr;             // source address
        struct in6_addr saddr6; // source address (IPv6)
        u32  daddr;             // destination address
        struct in6_addr daddr6; // destination address (IPv6)
        u8   thesource;         // I am the one originating packet
};

#endif // MINE_H_
