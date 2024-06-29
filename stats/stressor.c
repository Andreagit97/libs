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

	if(argc != 3)
	{
		fprintf(stderr, "Wrong number of params.\n");
		return EXIT_FAILURE;
	}

	struct timeval tval_start, tval_end, tval_result = {};

	// Each syscall generates 2 events
	uint64_t num_syscalls = strtoul(argv[1], NULL, 10) / 2;
	uint64_t interval_to_sleep_usec = strtoul(argv[2], NULL, 10);

	// printf("[DEBUG] Throughput required: %ld evt/s\n", num_syscalls*2);
	// printf("[DEBUG] Num syscall: %ld\n", num_syscalls);
	// printf("[DEBUG] Interval to sleep: %ld\n", interval_to_sleep_usec);

	printf("Start 'fstat' stressor with '%ld' evt/s\n", num_syscalls * 2);
	while(1)
	{
		gettimeofday(&tval_start, NULL);
		for(size_t i = 0; i < num_syscalls; i++)
		{
			syscall(__NR_fstat, -1, NULL);
			if(interval_to_sleep_usec && (i % 1000 == 0))
			{
				// we cannot call the usleep between each call because it costs too much
				usleep(interval_to_sleep_usec);
			}
		}
		gettimeofday(&tval_end, NULL);
		timersub(&tval_end, &tval_start, &tval_result);
		if(tval_result.tv_sec > 0)
		{
			printf("[WARNING] Time spent to generate the required throuhput: %ld.%06ld. We skip the "
			       "sleep\n",
			       tval_result.tv_sec, tval_result.tv_usec);
			continue;
		}
		// To complete the second we need to sleep this time.
		usleep(1000000 - (tval_result.tv_usec));
	}

	printf("Aborted\n");
	return EXIT_FAILURE;
}

// This doesn't work well

// #define SYSCALL_COST_USEC (0.415)
// #define SEC_TO_USEC 1000000

// int main(int argc, char** argv)
// {
// 	if(signal(SIGINT, signal_callback) == SIG_ERR)
// 	{
// 		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
// 		return EXIT_FAILURE;
// 	}

// 	if(argc != 2)
// 	{
// 		fprintf(stderr, "Wrong number of params. You should provide a throughput \n");
// 		return EXIT_FAILURE;
// 	}

// 	uint64_t num_syscalls = strtoul(argv[1], NULL, 10)/2;
// 	uint64_t num_usec_to_run = num_syscalls * SYSCALL_COST_USEC;
// 	uint64_t num_usec_to_sleep = SEC_TO_USEC - num_usec_to_run;
// 	uint64_t interval_to_sleep = num_usec_to_sleep/num_syscalls;

// 	// uint64_t num_usec_to_sleep = (SEC_TO_USEC - num_usec_to_run) / num_usec_to_run;
// 	// Debug
// 	printf("[DEBUG] Throughput required: %ld evt/s\n", num_syscalls*2);
// 	printf("[DEBUG] Num usec we need to run: %ld\n", num_usec_to_run);
// 	printf("[DEBUG] Num usec we need to sleep: %ld\n", num_usec_to_sleep);
// 	printf("[DEBUG] Interval to sleep: %ld\n", interval_to_sleep);

// 	while(1)
// 	{
// 		syscall(__NR_fstat, -1, NULL);
// 		usleep(interval_to_sleep);
// 	}

// 	printf("Aborted\n");
// 	return EXIT_FAILURE;
// }
