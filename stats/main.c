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
#include <sys/time.h>

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

	if(argc != 2)
	{
		fprintf(stderr, "Wrong number of params.\n");
		return EXIT_FAILURE;
	}
	
	struct timeval tval_start, tval_end, tval_result = {};

	int num_events = strtoul(argv[1], NULL, 10);
	printf("Start 'fstat' stressor with '%d' evt/s\n", num_events);
	while(1)
	{
		gettimeofday(&tval_start, NULL);
		// We increment by 2 because we have enter and exit events.
		for(size_t i = 0; i < num_events; i = i+2)
		{
			// It will always fail and it is defined on ARM64
			syscall(__NR_fstat, -1, NULL);
		}
		gettimeofday(&tval_end, NULL);
		timersub(&tval_end, &tval_start, &tval_result);
		if(tval_result.tv_sec > 0)
		{
			printf("Time spent to generate the required throuhput: %ld.%06ld. We skip the slepp\n", tval_result.tv_sec, tval_result.tv_usec);
			continue;
		}

		// To complete the second we need to sleep this time.
		uint64_t sleep_time_us = 1000000 - (tval_result.tv_usec);
		usleep(sleep_time_us);
	}

	printf("Aborted\n");
	return EXIT_FAILURE;
}
