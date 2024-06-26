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
	if(argc != 3)
	{
		fprintf(stderr, "Wrong number of params.\n");
		return EXIT_FAILURE;
	}

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return EXIT_FAILURE;
	}

	ssize_t num_cpus = sysconf(_SC_NPROCESSORS_CONF);
	if(num_cpus == -1)
	{
		fprintf(stderr, "cannot obtain the number of available CPUs from '_SC_NPROCESSORS_CONF'\n");
		return EXIT_FAILURE;
	}

	// - first CPU for init processes
	// - second CPU for scap-open
	for(int i = 2; i < num_cpus; i++)
	{
		int pid = fork();
		if(pid == 0)
		{
			const char* newargv[] = {"./../../main", argv[1], argv[2], NULL};
			syscall(__NR_execveat, AT_FDCWD, "./../../main", newargv, NULL, 0);
			fprintf(stderr, "failed to exec the stressor for cpu %d. %s: %d\n", i, strerror(errno), errno);
			return EXIT_FAILURE;
		}
		if(pid == -1)
		{
			fprintf(stderr, "failed to fork the stressor on CPU %d. %s: %d\n", i, strerror(errno), errno);
			return EXIT_FAILURE;
		}
		// to shift them in time
		usleep(50);
	}
	printf("Spawned '%ld' stressors\n", num_cpus - 2);
	return EXIT_SUCCESS;
}
