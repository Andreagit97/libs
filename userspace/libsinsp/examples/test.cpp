/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <iostream>
#include <iomanip>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sinsp.h>
#include <functional>

#ifdef __x86_64__
#include "./compact_x86.h"
#elif __aarch64__
#include "./compact_arm64.h"
#elif __s390x__
#include "./compact_s390x.h"
#endif /* __x86_64__ */


#include "util.h"

using namespace std;

static bool g_interrupted;
static const uint8_t g_backoff_timeout_secs = 2;
static bool g_all_threads = false;

sinsp_evt* get_event(sinsp& inspector);

#define PROCESS_DEFAULTS "*%evt.num %evt.time %evt.category %container.id %proc.ppid %proc.pid %evt.type %proc.exe %proc.cmdline %evt.args"

// Formatters used with JSON output
static sinsp_evt_formatter* default_formatter = nullptr;
static sinsp_evt_formatter* process_formatter = nullptr;
static sinsp_evt_formatter* net_formatter = nullptr;

extern const enum ppm_syscall_code g_syscall_code_routing_table[];
extern const struct syscall_evt_pair g_syscall_table[];

// Functions used for dumping to stdout
void plaintext_dump(sinsp& inspector);
void json_dump(sinsp& inspector);

static void sigint_handler(int signum)
{
	g_interrupted = true;
}

static void usage()
{
	string usage = R"(Usage: sinsp-example [options]

Options:
  -h, --help                    Print this page
  -f <filter>                   Filter string for events (see https://falco.org/docs/rules/supported-fields/ for supported fields)
  -j, --json                    Use JSON as the output format
  -a, --all-threads             Output information about all threads, not just the main one
)";
	cout << usage << endl;
}

std::set<uint32_t> ordered_sinsp_state_ppm_sc_set{
#ifdef __NR_accept
	PPM_SC_ACCEPT,
#endif

#ifdef __NR_accept4
	PPM_SC_ACCEPT4,
#endif

#ifdef __NR_bind
	PPM_SC_BIND,
#endif

#ifdef __NR_capset
	PPM_SC_CAPSET,
#endif

#ifdef __NR_chdir
	PPM_SC_CHDIR,
#endif

#ifdef __NR_chroot
	PPM_SC_CHROOT,
#endif

#ifdef __NR_clone
	PPM_SC_CLONE,
#endif

#ifdef __NR_clone3
	PPM_SC_CLONE3,
#endif

#ifdef __NR_close
	PPM_SC_CLOSE,
#endif

#ifdef __NR_connect
	PPM_SC_CONNECT,
#endif

#ifdef __NR_creat
	PPM_SC_CREAT,
#endif

#ifdef __NR_dup
	PPM_SC_DUP,
#endif

#ifdef __NR_dup2
	PPM_SC_DUP2,
#endif

#ifdef __NR_dup3
	PPM_SC_DUP3,
#endif

#ifdef __NR_eventfd
	PPM_SC_EVENTFD,
#endif

#ifdef __NR_eventfd2
	PPM_SC_EVENTFD2,
#endif

#ifdef __NR_execve
	PPM_SC_EXECVE,
#endif

#ifdef __NR_execveat
	PPM_SC_EXECVEAT,
#endif

#ifdef __NR_fchdir
	PPM_SC_FCHDIR,
#endif

#ifdef __NR_fcntl
	PPM_SC_FCNTL,
#endif

	PPM_SC_FCNTL64,

#ifdef __NR_fork
	PPM_SC_FORK,
#endif

#ifdef __NR_inotify_init
	PPM_SC_INOTIFY_INIT,
#endif

#ifdef __NR_inotify_init1
	PPM_SC_INOTIFY_INIT1,
#endif

#ifdef __NR_io_uring_setup
	PPM_SC_IO_URING_SETUP,
#endif

#ifdef __NR_mount
	PPM_SC_MOUNT,
#endif

#ifdef __NR_open
	PPM_SC_OPEN,
#endif

#ifdef __NR_open_by_handle_at
	PPM_SC_OPEN_BY_HANDLE_AT,
#endif

#ifdef __NR_openat
	PPM_SC_OPENAT,
#endif

#ifdef __NR_openat2
	PPM_SC_OPENAT2,
#endif

#ifdef __NR_pipe
	PPM_SC_PIPE,
#endif

#ifdef __NR_pipe2
	PPM_SC_PIPE2,
#endif

#ifdef __NR_prlimit64
	PPM_SC_PRLIMIT64,
#endif

#ifdef __NR_recvfrom
	PPM_SC_RECVFROM,
#endif

#ifdef __NR_recvmsg
	PPM_SC_RECVMSG,
#endif

#ifdef __NR_getsockopt
	PPM_SC_GETSOCKOPT, /// TODO: In the next future probably we could remove this from the state
#endif

#ifdef __NR_sendmsg
	PPM_SC_SENDMSG,
#endif

#ifdef __NR_sendto
	PPM_SC_SENDTO,
#endif

#ifdef __NR_setgid
	PPM_SC_SETGID,
#endif

	PPM_SC_SETGID32,

#ifdef __NR_setpgid
	PPM_SC_SETPGID,
#endif

#ifdef __NR_setresgid
	PPM_SC_SETRESGID,
#endif

	PPM_SC_SETRESGID32,

#ifdef __NR_setresuid
	PPM_SC_SETRESUID,
#endif

	PPM_SC_SETRESUID32,

#ifdef __NR_setrlimit
	PPM_SC_SETRLIMIT,
#endif

#ifdef __NR_setsid
	PPM_SC_SETSID,
#endif

#ifdef __NR_setuid
	PPM_SC_SETUID,
#endif

	PPM_SC_SETUID32,

#ifdef __NR_shutdown
	PPM_SC_SHUTDOWN,
#endif

#ifdef __NR_signalfd
	PPM_SC_SIGNALFD,
#endif

#ifdef __NR_signalfd4
	PPM_SC_SIGNALFD4,
#endif

#ifdef __NR_socket
	PPM_SC_SOCKET,
#endif

#ifdef __NR_socketpair
	PPM_SC_SOCKETPAIR,
#endif

#ifdef __NR_timerfd_create
	PPM_SC_TIMERFD_CREATE,
#endif

#ifdef __NR_umount2
	PPM_SC_UMOUNT2,
#endif

#ifdef __NR_userfaultfd
	PPM_SC_USERFAULTFD,
#endif

#ifdef __NR_vfork
	PPM_SC_VFORK,
#endif

#ifdef __NR_epoll_create
	PPM_SC_EPOLL_CREATE,
#endif

#ifdef __NR_epoll_create1
	PPM_SC_EPOLL_CREATE1,
#endif
};

//
// Sample filters:
//   "evt.category=process or evt.category=net"
//   "evt.dir=< and (evt.category=net or (evt.type=execveat or evt.type=execve or evt.type=clone or evt.type=fork or evt.type=vfork))"
//
int main(int argc, char** argv)
{
	sinsp inspector;
	std::set<uint32_t> ppm_sc_not_dropped;
	std::set<uint32_t> ppm_sc_generic;
	std::set<std::string> ppm_sc_not_dropped_names;

	std::unordered_set<uint32_t> ppm_sc_actual_falco_state = {
		PPM_SC_ACCEPT,
		PPM_SC_ACCEPT4,
		PPM_SC_BIND,
		PPM_SC_BPF,
		PPM_SC_CAPSET,
		PPM_SC_CHDIR,
		PPM_SC_CHMOD,
		PPM_SC_CHROOT,
		PPM_SC_CLONE,
		PPM_SC_CLONE3,
		PPM_SC_CLOSE,
		PPM_SC_CONNECT,
		PPM_SC_CREAT,
		PPM_SC_DUP,
		PPM_SC_DUP2,
		PPM_SC_DUP3,
		PPM_SC_EVENTFD,
		PPM_SC_EVENTFD2,
		PPM_SC_EXECVE,
		PPM_SC_EXECVEAT,
		PPM_SC_FCHDIR,
		PPM_SC_FCHMOD,
		PPM_SC_FCHMODAT,
		PPM_SC_FCNTL,
		PPM_SC_FCNTL64,
		PPM_SC_FLOCK,
		PPM_SC_FORK,
		PPM_SC_GETSOCKOPT,
		PPM_SC_INOTIFY_INIT,
		PPM_SC_INOTIFY_INIT1,
		PPM_SC_IOCTL,
		PPM_SC_IO_URING_SETUP,
		PPM_SC_KILL,
		PPM_SC_LINK,
		PPM_SC_LINKAT,
		PPM_SC_LISTEN,
		PPM_SC_MKDIR,
		PPM_SC_MKDIRAT,
		PPM_SC_MOUNT,
		PPM_SC_OPEN,
		PPM_SC_OPEN_BY_HANDLE_AT,
		PPM_SC_OPENAT,
		PPM_SC_OPENAT2,
		PPM_SC_PIPE,
		PPM_SC_PIPE2,
		PPM_SC_PRLIMIT64,
		PPM_SC_PTRACE,
		PPM_SC_QUOTACTL,
		PPM_SC_RECVFROM,
		PPM_SC_RECVMSG,
		PPM_SC_RENAME,
		PPM_SC_RENAMEAT,
		PPM_SC_RENAMEAT2,
		PPM_SC_RMDIR,
		PPM_SC_SECCOMP,
		PPM_SC_SENDMSG,
		PPM_SC_SENDTO,
		PPM_SC_SETGID,
		PPM_SC_SETGID32,
		PPM_SC_SETNS,
		PPM_SC_SETPGID,
		PPM_SC_SETRESGID,
		PPM_SC_SETRESGID32,
		PPM_SC_SETRESUID,
		PPM_SC_SETRESUID32,
		PPM_SC_SETRLIMIT,
		PPM_SC_SETSID,
		PPM_SC_SETUID,
		PPM_SC_SETUID32,
		PPM_SC_SHUTDOWN,
		PPM_SC_SIGNALFD,
		PPM_SC_SIGNALFD4,
		PPM_SC_SOCKET,
		PPM_SC_SOCKETPAIR,
		PPM_SC_SYMLINK,
		PPM_SC_SYMLINKAT,
		PPM_SC_TGKILL,
		PPM_SC_TIMERFD_CREATE,
		PPM_SC_TKILL,
		PPM_SC_UMOUNT2,
		PPM_SC_UNLINK,
		PPM_SC_UNLINKAT,
		PPM_SC_UNSHARE,
		PPM_SC_USERFAULTFD,
		PPM_SC_VFORK,
	};

	ppm_sc_actual_falco_state.insert(ordered_sinsp_state_ppm_sc_set.begin(), ordered_sinsp_state_ppm_sc_set.end());

	const struct ppm_syscall_desc* info_table = scap_get_syscall_info_table();

	// salviamo quelle non droppate
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		if(info_table[ppm_sc].flags & EF_DROP_SIMPLE_CONS)
		{
			continue;
		}
		ppm_sc_not_dropped.insert(ppm_sc);
	}

	// e riaggiungiamo quelle che non devono essere tolte, ci sono dei casi!
	for(int syscall_id = 0; syscall_id < PPM_SC_MAX; syscall_id++)
	{
		if(g_syscall_table[syscall_id].flags & UF_NEVER_DROP)
		{
			ppm_sc_not_dropped.insert(g_syscall_code_routing_table[syscall_id]);
		}
	}

	// take generic syscalls
	for(int syscall_id = 0; syscall_id < SYSCALL_TABLE_SIZE; syscall_id++)
	{
		if(g_syscall_table[syscall_id].enter_event_type == PPME_GENERIC_E && !(g_syscall_table[syscall_id].flags & UF_NEVER_DROP))
		{
			ppm_sc_generic.insert(g_syscall_code_routing_table[syscall_id]);
		}
	}

	for(auto ppm_sc : ppm_sc_generic)
	{
		ppm_sc_not_dropped.erase(ppm_sc);
	}


	// compare old simple consumer against new set


	printf("\nSyscall that are in the new set but not in the old\n");
	for(auto ppm_sc : ppm_sc_actual_falco_state)
	{
		if(ppm_sc_not_dropped.find(ppm_sc) == ppm_sc_not_dropped.end())
		{
			printf("- %s\n", info_table[ppm_sc].name);
		}
	}

	printf("\nSyscall that are in the old set but not in the new one\n");
	for(auto ppm_sc : ppm_sc_not_dropped)
	{
		if(ppm_sc_actual_falco_state.find(ppm_sc) == ppm_sc_actual_falco_state.end())
		{
			printf("- %s\n", info_table[ppm_sc].name);
		}
	}





	// for(auto ppm_sc : ppm_sc_not_dropped)
	// {
	// 	// switch (ppm_sc)
	// 	// {
	// 	// case PPM_SC_BDFLUSH:
	// 	// 	continue;
	// 	// }

	// 	ppm_sc_not_dropped_names.insert(info_table[ppm_sc].name);
	// }

	// std::cout << "\nPrint old drop simple consumer set without generics\n"
	// 	  << std::endl;
	// int i = 0;
	// for(auto name : ppm_sc_not_dropped_names)
	// {
	// 	i++;
	// 	printf("%d) %s\n", i, name.c_str());
	// }

	return 0;

	/////////////////////////////////////////////////////
	/////////////////////////////////////////////////////
	/////////////////////////////////////////////////////
	/////////////////////////////////////////////////////
	/////////////////////////////////////////////////////
	/////////////////////////////////////////////////////
	/////////////////////////////////////////////////////
	/////////////////////////////////////////////////////
	/////////////////////////////////////////////////////
	/////////////////////////////////////////////////////

	// Parse configuration options.
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"json", no_argument, 0, 'j'},
		{"all-threads", no_argument, 0, 'a'},
		{0, 0, 0, 0}};

	int op;
	int long_index = 0;
	string filter_string;
	std::function<void(sinsp & inspector)> dump = plaintext_dump;
	while((op = getopt_long(argc, argv,
				"hr:s:f:ja",
				long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'f':
			filter_string = optarg;
			break;
		case 'j':
			// Initialize JSON formatters
			default_formatter = new sinsp_evt_formatter(&inspector, DEFAULT_OUTPUT_STR);
			process_formatter = new sinsp_evt_formatter(&inspector, PROCESS_DEFAULTS);
			net_formatter = new sinsp_evt_formatter(&inspector, PROCESS_DEFAULTS " %fd.name");

			inspector.set_buffer_format(sinsp_evt::PF_JSON);
			dump = json_dump;
		case 'a':
			g_all_threads = true;
		default:
			break;
		}
	}

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);
	signal(SIGTERM, sigint_handler);

	inspector.open();

	if(!filter_string.empty())
	{
		try
		{
			inspector.set_filter(filter_string);
		}
		catch(const sinsp_exception& e)
		{
			cerr << "[ERROR] Unable to set filter: " << e.what() << endl;
		}
	}

	while(!g_interrupted)
	{
		dump(inspector);
	}

	// Cleanup JSON formatters
	delete default_formatter;
	delete process_formatter;
	delete net_formatter;

	return 0;
}

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error)
{
	sinsp_evt* ev = nullptr;
	int32_t res = inspector.next(&ev);

	if(res == SCAP_SUCCESS)
	{
		return ev;
	}

	if(res != SCAP_TIMEOUT)
	{
		handle_error(inspector.getlasterr());
		sleep(g_backoff_timeout_secs);
	}

	return nullptr;
}

void plaintext_dump(sinsp& inspector)
{
	sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
				  { cout << "[ERROR] " << error_msg << endl; });

	if(ev == nullptr)
	{
		return;
	}

	sinsp_threadinfo* thread = ev->get_thread_info();
	if(thread)
	{
		string cmdline;
		sinsp_threadinfo::populate_cmdline(cmdline, thread);

		if(g_all_threads || thread->is_main_thread())
		{
			string date_time;
			sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

			bool is_host_proc = thread->m_container_id.empty();
			cout << "[" << date_time << "]:["
			     << (is_host_proc ? "HOST" : thread->m_container_id) << "]:";

			cout << "[CAT=";

			if(ev->get_category() == EC_PROCESS)
			{
				cout << "PROCESS]:";
			}
			else if(ev->get_category() == EC_NET)
			{
				cout << get_event_category(ev->get_category()) << "]:";
				sinsp_fdinfo_t* fd_info = ev->get_fd_info();

				// event subcategory should contain SC_NET if ipv4/ipv6
				if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
				{
					cout << "[" << fd_info->tostring() << "]:";
				}
			}
			else if(ev->get_category() == EC_IO_READ || ev->get_category() == EC_IO_WRITE)
			{
				cout << get_event_category(ev->get_category()) << "]:";

				sinsp_fdinfo_t* fd_info = ev->get_fd_info();
				if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
				{
					cout << "[" << fd_info->tostring() << "]:";
				}
			}
			else
			{
				cout << get_event_category(ev->get_category()) << "]:";
			}

			sinsp_threadinfo* p_thr = thread->get_parent_thread();
			int64_t parent_pid = -1;
			if(nullptr != p_thr)
			{
				parent_pid = p_thr->m_pid;
			}

			cout << "[PPID=" << parent_pid << "]:"
			     << "[PID=" << thread->m_pid << "]:"
			     << "[TYPE=" << get_event_type(ev->get_type()) << "]:"
			     << "[EXE=" << thread->get_exepath() << "]:"
			     << "[CMD=" << cmdline << "]"
			     << endl;
		}
	}
	else
	{
		cout << "[EVENT]:[" << get_event_category(ev->get_category()) << "]:"
		     << ev->get_name() << endl;
	}
}

void json_dump(sinsp& inspector)
{
	// Initialize JSON formatters
	static sinsp_evt_formatter* default_formatter = new sinsp_evt_formatter(&inspector, DEFAULT_OUTPUT_STR);
	static sinsp_evt_formatter* process_formatter = new sinsp_evt_formatter(&inspector, PROCESS_DEFAULTS);
	static sinsp_evt_formatter* net_formatter = new sinsp_evt_formatter(&inspector, PROCESS_DEFAULTS " %fd.name");

	sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
				  { cout << R"({"error": ")" << error_msg << R"("})" << endl; });

	if(ev == nullptr)
	{
		return;
	}

	std::string output;
	sinsp_threadinfo* thread = ev->get_thread_info();

	if(thread)
	{
		if(g_all_threads || thread->is_main_thread())
		{
			if(ev->get_category() == EC_PROCESS)
			{
				process_formatter->tostring(ev, output);
			}
			else if(ev->get_category() == EC_NET || ev->get_category() == EC_IO_READ || ev->get_category() == EC_IO_WRITE)
			{
				net_formatter->tostring(ev, output);
			}
			else
			{
				default_formatter->tostring(ev, output);
			}
		}
		else
		{
			// Prevent empty lines from being printed
			return;
		}
	}
	else
	{
		default_formatter->tostring(ev, output);
	}

	cout << output << std::endl;
}
