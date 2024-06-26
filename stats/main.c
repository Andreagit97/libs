#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* to get O_PATH, AT_EMPTY_PATH */
#endif
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

static void signal_callback(int signal)
{
	printf("\nStop\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char** argv)
{
	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return EXIT_FAILURE;
	}

	if(argc != 3)
	{
		fprintf(stderr, "Wrong number of params.\n");
		return EXIT_FAILURE;
	}

	int num_iteration = strtoul(argv[1], NULL, 10);
	int sleep_time_us = strtoul(argv[2], NULL, 10);
	printf("Start openat stressor with '%d' iterations and '%d' us of sleep\n", num_iteration, sleep_time_us);
	while(1)
	{
		// Note that we are using failed syscalls to increase the throughput
		// Moreover the syscall fails so we don't populate a new file-descriptor
		for(size_t i = 0; i < num_iteration; i++)
		{
			syscall(SYS_openat, AT_FDCWD, "aaaaaaaaaa", 0);
		}
		usleep(sleep_time_us);
	}

	printf("Aborted\n");
	return EXIT_FAILURE;
}
