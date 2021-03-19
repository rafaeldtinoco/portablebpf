#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

int main(int argc, char **argv)
{
	if (argc != 4)
		exit(-1);

	printf("%lu\n", KERNEL_VERSION(atol(argv[1]), atol(argv[2]), atol(argv[3])));
}
