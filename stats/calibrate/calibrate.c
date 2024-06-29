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

#define NUMBER_OF_CALLS 20000000
#define SEC_TO_USEC 1000000

int main(int argc, char** argv)
{
	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return EXIT_FAILURE;
	}

	struct timeval tval_start, tval_end, tval_result = {};
	gettimeofday(&tval_start, NULL);

	uint64_t counter = 0;
	while(counter < NUMBER_OF_CALLS)
	{
		syscall(__NR_fstat, -1, NULL);
		counter++;
	}

	gettimeofday(&tval_end, NULL);
	timersub(&tval_end, &tval_start, &tval_result);
	printf("Number of calls/usec: %f call/usec\n",
	       (double)NUMBER_OF_CALLS / (double)(tval_result.tv_sec * SEC_TO_USEC + tval_result.tv_usec));
	return EXIT_SUCCESS;
}
