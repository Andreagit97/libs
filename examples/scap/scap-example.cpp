#include <iostream>
#include <string>
#include <scap.h>
#include <getopt.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/time.h>
#include <fcntl.h>
#include <fstream>
#include <json/json.h>

/* CLI options */
#define HELP_OPTION "help"
#define KMOD_OPTION "kmod"
#define BPF_OPTION "bpf"
#define MODERN_BPF_OPTION "modern-bpf"
#define SCAP_FILE_OPTION "scap_file"
#define BUFFER_OPTION "buffer-dim"
#define NUM_EVENTS_OPTION "num_events"
#define TP_OPTION "tp"
#define PPM_SC_OPTION "ppm_sc"
#define SIMPLE_SET_OPTION "simple_set"
#define ALL_OPTION "all"
#define JSON_OPTION "json"

/* Default values */
#define UNKNOWN_ENGINE "unknown"
#define JSON_DEFAULT_PATH "./examples/scap/scap-example-output.json"
#define BPF_PROBE_DEFAULT_PATH "/driver/bpf/probe.o"
#define KMOD_DEFAULT_PATH "/driver/scap.ko"
#define KMOD_NAME "scap"
#define LOG_PREFIX "[SCAP-OPEN]: "

#define log_err(x) std::cerr << LOG_PREFIX << x << std::endl;
#define log_info(x) std::cout << LOG_PREFIX << x << std::endl;

extern const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE];
static const struct ppm_syscall_desc* g_syscall_info_table;
static struct timeval tval_start, tval_end, tval_result;
static unsigned long timeouts;				 /* Times in which there were no events in the buffer. */
static unsigned long scap_nexts;			 /* Times in which the 'scap-next' method is called. */
static unsigned long captured_events;			 /* Total number of events captured by the scap-example. */
static unsigned long max_events_to_capture = UINT64_MAX; /* Total number of events we want to capture */
static std::string json_output_path;
scap_t* handle = NULL;

int remove_kmod()
{
	if(syscall(__NR_delete_module, KMOD_NAME, O_NONBLOCK))
	{
		switch(errno)
		{
		case ENOENT:
			return EXIT_SUCCESS;

		/* If a module has a nonzero reference count with `O_NONBLOCK` flag
		 * the call returns immediately, with `EWOULDBLOCK` code. So in that
		 * case we wait until the module is detached.
		 */
		case EWOULDBLOCK:
			for(int i = 0; i < 4; i++)
			{
				int ret = syscall(__NR_delete_module, KMOD_NAME, O_NONBLOCK);
				if(ret == 0 || errno == ENOENT)
				{
					return EXIT_SUCCESS;
				}
				sleep(1);
			}
			log_err("Unable to remove kernel module, it is still injected. Errno message: " << strerror(errno) << ", errno: " << errno);
			return EXIT_FAILURE;

		case EBUSY:
		case EFAULT:
		case EPERM:
			log_err("Unable to remove kernel module. Errno message: " << strerror(errno) << ", errno: " << errno);
			return EXIT_FAILURE;

		default:
			log_err("Unexpected error code. Errno message: " << strerror(errno) << ", errno: " << errno);
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

int insert_kmod(const std::string& kmod_path)
{
	/* Here we want to insert the module if we fail we need to abort the program. */
	int fd = open(kmod_path.c_str(), O_RDONLY);
	if(fd < 0)
	{
		log_err("Unable to open the kmod file. Errno message: " << strerror(errno) << ", errno: " << errno);
		return EXIT_FAILURE;
	}

	if(syscall(__NR_finit_module, fd, "", 0))
	{
		log_err("Unable to inject the kmod. Errno message: " << strerror(errno) << ", errno: " << errno);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

void abort_if_already_configured(scap_open_args* oargs)
{
	if(strcmp(oargs->engine_name, UNKNOWN_ENGINE) != 0)
	{
		log_err("* '" << oargs->engine_name << "' engine is already configured. Please specify just one engine!");
		exit(EXIT_FAILURE);
	}
}

void print_menu_and_exit()
{
	std::string usage = R"(Usage: drivers_test [options]

Overview: The goal of this binary is to run tests against one of our drivers.

Options:
  -k, --kmod <path>       Run tests against the kernel module. Default path is `./driver/scap.ko`.
  -m, --modern-bpf        Run tests against the modern bpf probe.
  -b, --bpf <path>        Run tests against the bpf probe. Default path is `./driver/bpf/probe.o`.
  -d, --buffer-dim <dim>  Change the dimension of shared buffers between userspace and kernel. You must specify the dimension in bytes.
  -h, --help              This page.
)";
	std::cout << usage << std::endl;
	exit(EXIT_SUCCESS);
}

void print_supported_tracepoints()
{
	printf("\n------- Supported tracepoints: \n");

	for(int j = 0; j < TP_VAL_MAX; j++)
	{
		printf("- %-25s tp_code: (%d)\n", tp_names[j], j);
	}
}

void print_supported_syscalls()
{
	printf("\n------- Supported syscalls: \n");

	for(int syscall_nr = 0; syscall_nr < SYSCALL_TABLE_SIZE; syscall_nr++)
	{
		if(g_syscall_table[syscall_nr].ppm_sc == PPM_SC_UNKNOWN)
		{
			continue;
		}
		int ppm_code = g_syscall_table[syscall_nr].ppm_sc;
		printf("- %-25s system_code: (%d) ppm_code: (%d)\n", g_syscall_info_table[ppm_code].name, syscall_nr, ppm_code);
	}
}

void print_enabled_syscalls(scap_open_args* oargs)
{
	printf("---------------------- INTERESTING SYSCALLS ----------------------\n");
	printf("* Syscalls enabled:\n");
	for(int j = 0; j < PPM_SC_MAX; j++)
	{
		if(oargs->ppm_sc_of_interest.ppm_sc[j])
		{
			printf("- %s\n", g_syscall_info_table[j].name);
		}
	}
	printf("------------------------------------------------------------------\n\n");
}

void print_enabled_traceoints(scap_open_args* oargs)
{
	printf("---------------------- ENABLED TRACEPOINTS ----------------------\n");
	printf("* Tracepoints enabled:\n");
	for(int j = 0; j < TP_VAL_MAX; j++)
	{
		if(oargs->tp_of_interest.tp[j])
		{
			printf("- %s\n", tp_names[j]);
		}
	}
	printf("-----------------------------------------------------------------\n\n");
}

scap_t* open_engine(int argc, char** argv)
{

	static struct option long_options[] = {
		{BPF_OPTION, optional_argument, 0, 'b'},
		{MODERN_BPF_OPTION, no_argument, 0, 'm'},
		{KMOD_OPTION, optional_argument, 0, 'k'},
		{BUFFER_OPTION, required_argument, 0, 'd'},
		{SCAP_FILE_OPTION, required_argument, 0, 'f'},
		{NUM_EVENTS_OPTION, required_argument, 0, 'n'},
		{TP_OPTION, required_argument, 0, 't'},
		{PPM_SC_OPTION, required_argument, 0, 'p'},
		{SIMPLE_SET_OPTION, no_argument, 0, 's'},
		{ALL_OPTION, no_argument, 0, 'a'},
		{JSON_OPTION, optional_argument, 0, 'j'},
		{HELP_OPTION, no_argument, 0, 'h'},
		{0, 0, 0, 0}};

	int ret = 0;
	scap_open_args oargs = {0};
	struct scap_bpf_engine_params bpf_params = {0};
	struct scap_kmod_engine_params kmod_params = {0};
	struct scap_modern_bpf_engine_params modern_bpf_params = {0};
	struct scap_savefile_engine_params savefile_params = {0};

	uint32_t ppm_sc_array[PPM_SC_MAX] = {0};
	oargs.engine_name = UNKNOWN_ENGINE;
	oargs.mode = SCAP_MODE_LIVE;
	unsigned long buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;
	std::string kmod_path;
	int tp = 0;
	int ppm_sc = 0;

	/* Get the syscall info table */
	g_syscall_info_table = scap_get_syscall_info_table();

	/* Remove kmod if injected, we remove it always even if we use another engine
	 * in this way we are sure the unique driver in the system is the one we will use.
	 */
	if(remove_kmod())
	{
		return NULL;
	}

	/* Get current cwd */
	char cwd[FILENAME_MAX];
	if(!getcwd(cwd, FILENAME_MAX))
	{
		std::cerr << "Unable to get current dir" << std::endl;
		return NULL;
	}

	/* Parse CLI options */
	int op = 0;
	int long_index = 0;
	while((op = getopt_long(argc, argv,
				"b::mk::d:f:n:t:p:saj::h",
				long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'b':
			abort_if_already_configured(&oargs);
			oargs.engine_name = BPF_ENGINE;
			bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			/* This should handle cases where we pass arguments with the space:
			 * `-b ./path/to/probe`. Without this `if` case we can accept arguments
			 * only in this format `-b./path/to/probe`
			 */
			if(optarg == NULL && optind < argc && argv[optind][0] != '-')
			{
				bpf_params.bpf_probe = argv[optind++];
			}
			else if(optarg == NULL)
			{
				bpf_params.bpf_probe = strncat(cwd, BPF_PROBE_DEFAULT_PATH, FILENAME_MAX - strlen(cwd));
			}
			else
			{
				bpf_params.bpf_probe = optarg;
			}
			oargs.engine_params = &bpf_params;
			log_info("* Configure BPF probe! Probe path: " << bpf_params.bpf_probe);
			break;

		case 'm':
			abort_if_already_configured(&oargs);
			oargs.engine_name = MODERN_BPF_ENGINE;
			modern_bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			oargs.engine_params = &modern_bpf_params;
			log_info("* Configure modern BPF probe!");
			break;

		case 'k':
			abort_if_already_configured(&oargs);
			oargs.engine_name = KMOD_ENGINE;
			kmod_params.buffer_bytes_dim = buffer_bytes_dim;
			if(optarg == NULL && optind < argc && argv[optind][0] != '-')
			{
				kmod_path = argv[optind++];
			}
			else if(optarg == NULL)
			{
				kmod_path = strncat(cwd, KMOD_DEFAULT_PATH, FILENAME_MAX - strlen(cwd));
			}
			else
			{
				kmod_path = optarg;
			}
			oargs.engine_params = &kmod_params;
			if(insert_kmod(kmod_path))
			{
				return NULL;
			}
			log_info("* Configure kernel module! Kernel module path: " << kmod_path);
			break;

		case 'f':
			abort_if_already_configured(&oargs);
			oargs.engine_name = SAVEFILE_ENGINE;
			oargs.mode = SCAP_MODE_CAPTURE;
			savefile_params.fname = optarg;
			oargs.engine_params = &savefile_params;
			log_info("* Configure scap-file capture! File path: " << savefile_params.fname);
			break;

		case 't':
			tp = atoi(optarg);
			if(tp < 0 || tp >= TP_VAL_MAX)
			{
				log_err("tp '" << tp << "' is not a valid tracepoint code!");
				print_supported_tracepoints();
				return NULL;
			}
			oargs.tp_of_interest.tp[tp] = 1;
			break;

		case 'p':
			ppm_sc = atoi(optarg);
			if(ppm_sc <= 0 || ppm_sc >= PPM_SC_MAX)
			{
				log_err("ppm_sc '" << ppm_sc << "' is not a valid PPM_SC code!");
				print_supported_syscalls();
				return NULL;
			}
			oargs.ppm_sc_of_interest.ppm_sc[ppm_sc] = 1;
			break;

		case 's':
			oargs.tp_of_interest.tp[SYS_ENTER] = true;
			oargs.tp_of_interest.tp[SYS_EXIT] = true;
			if(scap_get_modifies_state_ppm_sc(ppm_sc_array) != SCAP_SUCCESS)
			{
				log_err("Unable to use the simple set!");
				return NULL;
			}
			for(int i = 0; i < PPM_SC_MAX; i++)
			{
				if(ppm_sc_array[i])
				{
					oargs.ppm_sc_of_interest.ppm_sc[i] = true;
				}
			}
			break;

		case 'a':
			for(int i = 0; i < TP_VAL_MAX; i++)
			{
				oargs.tp_of_interest.tp[i] = true;
			}

			for(int i = 0; i < PPM_SC_MAX; i++)
			{
				oargs.ppm_sc_of_interest.ppm_sc[i] = true;
			}
			break;

		case 'j':
			if(optarg == NULL && optind < argc && argv[optind][0] != '-')
			{
				json_output_path = argv[optind++];
			}
			else if(optarg == NULL)
			{
				json_output_path = JSON_DEFAULT_PATH;
			}
			else
			{
				json_output_path = optarg;
			}
			log_info("* JSON report enabled! Output file: " << json_output_path);
			break;

		case 'n':
			max_events_to_capture = strtoul(optarg, NULL, 10);
			break;

		case 'd':
			buffer_bytes_dim = strtoul(optarg, NULL, 10);
			/* We need to refresh the dimension in all engines, we don't know
			 * which one has been selected.
			 */
			kmod_params.buffer_bytes_dim = buffer_bytes_dim;
			bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			modern_bpf_params.buffer_bytes_dim = buffer_bytes_dim;
			break;

		case 'h':
			print_menu_and_exit();
			break;

		default:
			break;
		}
	}
	log_info("* Using buffer dim: " << buffer_bytes_dim);
	log_info("* Number of events to capture: " << max_events_to_capture);

	if(strcmp(oargs.engine_name, UNKNOWN_ENGINE) == 0)
	{
		log_err("Unsupported engine!");
		return NULL;
	}

	char error_buffer[FILENAME_MAX] = {0};
	scap_t* h = scap_open(&oargs, error_buffer, &ret);
	if(!h)
	{
		log_err("Unable to open the engine: " << error_buffer);
		return NULL;
	}
	log_info("* Engine correctly opened!");
	print_enabled_syscalls(&oargs);
	print_enabled_traceoints(&oargs);
	return h;
}

void print_stats()
{
	unsigned long event_per_seconds = 0;
	gettimeofday(&tval_end, NULL);
	timersub(&tval_end, &tval_start, &tval_result);
	if(tval_result.tv_sec != 0)
	{
		event_per_seconds = captured_events / tval_result.tv_sec;
	}
	scap_stats s;
	scap_get_stats(handle, &s);

	if(!json_output_path.empty())
	{
		log_info("Print results into: " << json_output_path);
		Json::Value stats;

		/* If not there it creates a new file, otherwise it overwrites the existing one. */
		std::ofstream outfile(json_output_path);
		stats["capturedByUserspace"] = Json::UInt64(captured_events);
		stats["seenByDrivers"] = Json::UInt64(s.n_evts);
		stats["timeElapsed"] = Json::UInt64(tval_result.tv_sec);
		stats["eventPerSecond"] = Json::UInt64(event_per_seconds);
		stats["drops"] = Json::UInt64(s.n_drops);
		stats["timeouts"] = Json::UInt64(timeouts);
		stats["scapNext"] = Json::UInt64(scap_nexts);
		outfile << stats << std::endl;
		outfile.close();
	}
	else
	{
		printf("\n---------------------- STATS -----------------------\n");
		printf("Events correctly captured by userspace (SCAP_SUCCESS): %" PRIu64 "\n", captured_events);
		printf("Seen by driver: %" PRIu64 "\n", s.n_evts);
		printf("Time elapsed: %ld s\n", tval_result.tv_sec);
		printf("Number of events/per-second: %ld\n", event_per_seconds);
		printf("Number of dropped events: %" PRIu64 "\n", s.n_drops);
		printf("Number of timeouts: %ld\n", timeouts);
		printf("Number of 'next' calls: %ld\n", scap_nexts);
		printf("Number of dropped events caused by full buffer (total / all buffer drops - includes all categories below, likely higher than sum of syscall categories): %" PRIu64 "\n", s.n_drops_buffer);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_clone_fork_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_clone_fork_enter);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_clone_fork_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_clone_fork_exit);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_execve_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_execve_enter);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_execve_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_execve_exit);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_connect_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_connect_enter);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_connect_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_connect_exit);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_open_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_open_enter);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_open_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_open_exit);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_dir_file_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_dir_file_enter);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_dir_file_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_dir_file_exit);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_other_interest_enter syscall category): %" PRIu64 "\n", s.n_drops_buffer_other_interest_enter);
		printf("Number of dropped events caused by full buffer (n_drops_buffer_other_interest_exit syscall category): %" PRIu64 "\n", s.n_drops_buffer_other_interest_exit);
		printf("Number of dropped events caused by full scratch map: %" PRIu64 "\n", s.n_drops_scratch_map);
		printf("Number of dropped events caused by invalid memory access (page faults): %" PRIu64 "\n", s.n_drops_pf);
		printf("Number of dropped events caused by an invalid condition in the kernel instrumentation (bug): %" PRIu64 "\n", s.n_drops_bug);
		printf("Number of preemptions: %" PRIu64 "\n", s.n_preemptions);
		printf("Number of events skipped due to the tid being in a set of suppressed tids: %" PRIu64 "\n", s.n_suppressed);
		printf("Number of threads currently being suppressed: %" PRIu64 "\n", s.n_tids_suppressed);
		printf("-----------------------------------------------------\n");
	}
	log_info("Bye!");
}

static void signal_callback(int signal)
{
	print_stats();
	exit(EXIT_SUCCESS);
}

int main(int argc, char** argv)
{
	int res = EXIT_SUCCESS;
	scap_evt* ev = NULL;
	uint16_t cpuid = 0;

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		log_err("An error occurred while setting SIGINT signal handler.");
		return EXIT_FAILURE;
	}

	/* Open the requested engine */
	handle = open_engine(argc, argv);
	if(!handle)
	{
		return EXIT_FAILURE;
	}

	gettimeofday(&tval_start, NULL);

	log_info("* Starting capture!");

	if(scap_start_capture(handle) != SCAP_SUCCESS)
	{
		log_err("Error in starting the capture: " << scap_getlasterr(handle));
		goto cleanup;
	}

	while(captured_events != max_events_to_capture)
	{
		res = scap_next(handle, &ev, &cpuid);
		scap_nexts++;
		if(res == SCAP_UNEXPECTED_BLOCK)
		{
			res = scap_restart_capture(handle);
			if(res == SCAP_SUCCESS)
			{
				continue;
			}
		}
		if(res == SCAP_TIMEOUT || res == SCAP_FILTERED_EVENT)
		{
			timeouts++;
			continue;
		}
		else if(res == SCAP_EOF)
		{
			log_info("* EOF after: " << captured_events << " events");
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			log_err("Error during the capture: " << scap_getlasterr(handle));
			goto cleanup;
		}
		captured_events++;
	}

cleanup:
	scap_stop_capture(handle);
	print_stats();
	scap_close(handle);
	remove_kmod();
	return res;
}