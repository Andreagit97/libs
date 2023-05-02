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

#pragma once

#ifndef VISIBILITY_PRIVATE
#define VISIBILITY_PRIVATE private:
#endif

#ifdef _WIN32
struct iovec {
	void  *iov_base;    /* Starting address */
	size_t iov_len;     /* Number of bytes to transfer */
};
#else
#include <sys/uio.h>
#endif

#include <functional>
#include <memory>
#include <set>
#include "fdinfo.h"
#include "internal_metrics.h"

class sinsp_delays_info;
class sinsp_tracerparser;
class blprogram;

typedef struct erase_fd_params
{
	bool m_remove_from_table;
	int64_t m_fd;
	sinsp_threadinfo* m_tinfo;
	sinsp_fdinfo_t* m_fdinfo;
	uint64_t m_ts;
}erase_fd_params;

class sinsp_threadinfo;

/* New struct that keep information regarding the thread group */
typedef struct thread_group_info
{
	thread_group_info(int64_t group_pid, bool reaper, std::weak_ptr<sinsp_threadinfo> current_thread):
		m_pid(group_pid),
		m_reaper(reaper){
			/* When we create the thread group info the count is 1, because we only have the creator thread */
			m_alive_count = 1;
			m_threads.push_front(current_thread);
		 };	

	inline void increment_thread_count()
	{
		m_alive_count++;
	}

	inline void decrement_thread_count()
	{
		m_alive_count--;
	}

	inline uint64_t get_thread_count() const
	{
		return m_alive_count;
	}

	inline bool is_reaper() const
	{
		return m_reaper;
	}

	inline void set_reaper()
	{
		m_reaper = true;
	}

	inline int64_t get_tgroup_pid() const
	{
		return m_pid;
	}

	inline const std::list<std::weak_ptr<sinsp_threadinfo>>& get_thread_list() const
	{
		return m_threads;
	}

	inline void add_thread_to_the_group(std::shared_ptr<sinsp_threadinfo> thread, bool main) 
	{
		/* The main thread should always be the first element of the list, if present.
	 	 * In this way we can efficiently obtain the main thread.
	 	 */
		if(main)
		{
			m_threads.push_front(thread);
		}
		else
		{
			m_threads.push_back(thread);
		}
		/* we are adding a thread so we increment the count */
		m_alive_count++;
	}

	inline sinsp_threadinfo* get_first_thread() const 
	{
		return m_threads.front().lock().get();
	}

VISIBILITY_PRIVATE
  int64_t m_pid; /* unsigned if we want to use `-1` as an invalid value */
  uint64_t m_alive_count;
  std::list<std::weak_ptr<sinsp_threadinfo>> m_threads;
  bool m_reaper;
}thread_group_info;


/** @defgroup state State management
 *  @{
 */

/*!
  \brief Thread/process information class.
  This class contains the full state for a thread, and a bunch of functions to
  manipulate threads and retrieve thread information.

  \note As a library user, you won't need to construct thread objects. Rather,
   you get them by calling \ref sinsp_evt::get_thread_info or
   \ref sinsp::get_thread.
  \note sinsp_threadinfo is also used to keep process state. For the sinsp
   library, a process is just a thread with TID=PID.
*/
class SINSP_PUBLIC sinsp_threadinfo
{
public:
	sinsp_threadinfo(sinsp *inspector = nullptr);
	virtual ~sinsp_threadinfo();

	/*!
	  \brief Return the name of the process containing this thread, e.g. "top".
	*/
	std::string get_comm() const;

	/*!
	  \brief Return the name of the process containing this thread from argv[0], e.g. "/bin/top".
	*/
	std::string get_exe() const;

	/*!
	  \brief Return the full executable path of the process containing this thread, e.g. "/bin/top".
	*/
	std::string get_exepath() const;

	/*!
	  \brief Return the working directory of the process containing this thread.
	*/
	std::string get_cwd();

	/*!
	  \brief Return the values of all environment variables for the process
	  containing this thread.
	*/
	const std::vector<std::string>& get_env();

	/*!
	  \brief Return the value of the specified environment variable for the process
	  containing this thread. Returns empty string if variable is not found.
	*/
	std::string get_env(const std::string& name);

	/*!
	  \brief Return true if this is a process' main thread.
	*/
	inline bool is_main_thread() const
	{
		return (m_tid == m_pid) || m_flags & PPM_CL_IS_MAIN_THREAD;
	}

	/*!
	  \brief Return true if the thread is invalid. Sometimes we create some
	  invalid thread info, if we are not able to scan proc.
	*/
	inline bool is_invalid() const
	{
		return m_tid < 0 || m_pid < 0 || m_ptid < 0;
	}

	/*!
	  \brief Return true if the thread is dead.
	*/
	inline bool is_dead() const
	{
		return m_flags & PPM_CL_CLOSED;
	}

	/*!
	  \brief Mark thread as dead.
	*/
	inline void set_dead()
	{
		m_flags |= PPM_CL_CLOSED;
	}

    /*!
      \brief Return the number of alive threads in the thread group, including the thread leader.
    */
    inline uint64_t get_num_threads() const
    {
        return m_tginfo ? m_tginfo->get_thread_count() : 0;
    }

    /*!
      \brief Return the number of alive threads in the thread group, excluding the thread leader.
    */
    inline uint64_t get_num_not_leader_threads() const
    {
        if(!m_tginfo)
        {
            return 0;
        }
        
        auto main_thread = get_main_thread();
        if(main_thread != nullptr && !main_thread->is_dead())
        {
            return m_tginfo->get_thread_count()-1;
        }
        /* we don't have the main thread in the group or it is dead */
        return m_tginfo->get_thread_count();
    }

	/*
	  \brief returns true if there is a loop detected in the thread parent state.
	  Needs traverse_parent_state() to have been called first.
	*/
	inline bool parent_loop_detected() const
	{
		return m_parent_loop_detected;
	}

	/*!
	  \brief Get the main thread of the process containing this thread.
	*/
	inline sinsp_threadinfo* get_main_thread() const
	{
		/* Here we could use the first element of our list */
		/* This is possible when we have invalid threads
		 */
		if(m_tginfo == nullptr)
		{
			return nullptr;
		}

		/* If we have the main thread in the group, it is always the first one */
		auto possible_main = m_tginfo->get_first_thread();
		if(possible_main == nullptr || !possible_main->is_main_thread())
		{
			return nullptr;
		}
		return possible_main;
	}

	/*!
	  \brief Get the process that launched this thread's process.
	*/
	sinsp_threadinfo* get_parent_thread();

	/*!
	  \brief Retrieve information about one of this thread/process FDs.

	  \param fd The file descriptor number, e.g. 0 for stdin.

	  \return Pointer to the FD information, or NULL if the given FD doesn't
	   exist
	*/
	inline sinsp_fdinfo_t* get_fd(int64_t fd)
	{
		if(fd < 0)
		{
			return NULL;
		}

		sinsp_fdtable* fdt = get_fd_table();

		if(fdt)
		{
			sinsp_fdinfo_t *fdinfo = fdt->find(fd);
			if(fdinfo)
			{
				// Its current name is now its old
				// name. The name might change as a
				// result of parsing.
				fdinfo->m_oldname = fdinfo->m_name;
				return fdinfo;
			}
		}

		return NULL;
	}

	/*!
	  \brief Return true if this thread is bound to the given server port.
	*/
	bool is_bound_to_port(uint16_t number);

	/*!
	  \brief Return true if this thread has a client socket open on the given port.
	*/
	bool uses_client_port(uint16_t number);

	void* get_private_state(uint32_t id);

	/*!
	  \brief Return the ratio between open FDs and maximum available FDs for this thread.
	*/
	uint64_t get_fd_usage_pct();
	double get_fd_usage_pct_d();

	/*!
	  \brief Return the number of open FDs for this thread.
	*/
	uint64_t get_fd_opencount() const;

	/*!
	  \brief Return the maximum number of FDs this thread can open.
	*/
	uint64_t get_fd_limit();

	/*!
	  \brief Return the cgroup name for a specific subsystem
	 */
	 const std::string& get_cgroup(const std::string& subsys) const;

	//
	// Walk up the parent process hierarchy, calling the provided
	// function for each node. If the function returns false, the
	// traversal stops.
	//
	typedef std::function<bool (sinsp_threadinfo *)> visitor_func_t;
	void traverse_parent_state(visitor_func_t &visitor);

	void assign_children_to_reaper(sinsp_threadinfo* reaper);

	// Note that the provided tid, a thread in this main thread's
	// pid, has been used in an exec enter event. In the
	// corresponding exec exit event, the threadinfo for this tid
	// will be removed, as it no longer exists.
	void set_exec_enter_tid(int64_t tid);

	// Fill in the provided tid with any tid set in
	// set_exec_enter_tid(). Returns true if a tid was set, false
	// otherwise.
	bool get_exec_enter_tid(int64_t* tid);

	// Clear any value set in set_exec_enter_tid
	void clear_exec_enter_tid();

	static void populate_cmdline(std::string &cmdline, const sinsp_threadinfo *tinfo);

	// Return true if this thread is a part of a healthcheck,
	// readiness probe, or liveness probe.
	bool is_health_probe();

	/*!
	  \brief Translate a directory's file descriptor into its path
	  \param dir_fd  A file descriptor for a directory
	  \return  A path (or "" if failure)
	 */
	std::string get_path_for_dir_fd(int64_t dir_fd);

	void set_user(uint32_t uid);
	void set_group(uint32_t gid);
	void set_loginuser(uint32_t loginuid);

	using cgroups_t = std::vector<std::pair<std::string, std::string>>;
	cgroups_t& cgroups() const;

	// In rare cases, a thread may do an exec, which results in
	// the thread having its tid reset to be the main thread of
	// the pid and all other threads for the pid being destroyed.
	//
	// We need to keep track of the tid that started the exec so
	// when parsing the exec exit event, we delete the thread that
	// performed the exec, as it is now the main thread of the new
	// pid.
	std::unique_ptr<int64_t> m_exec_enter_tid;

	//
	// Core state
	//
	int64_t m_tid;  ///< The id of this thread
	int64_t m_pid; ///< The id of the process containing this thread. In single thread threads, this is equal to tid.
	int64_t m_ptid; ///< The id of the process that started this thread.
	int64_t m_sid; ///< The session id of the process containing this thread.
	std::string m_comm; ///< Command name (e.g. "top")
	std::string m_exe; ///< argv[0] (e.g. "sshd: user@pts/4")
	std::string m_exepath; ///< full executable path
	bool m_exe_writable;
	bool m_exe_upper_layer; ///< True if the executable file belongs to upper layer in overlayfs
	std::vector<std::string> m_args; ///< Command line arguments (e.g. "-d1")
	std::vector<std::string> m_env; ///< Environment variables
	std::unique_ptr<cgroups_t> m_cgroups; ///< subsystem-cgroup pairs
	std::string m_container_id; ///< heuristic-based container id
	uint32_t m_flags; ///< The thread flags. See the PPM_CL_* declarations in ppm_events_public.h.
	int64_t m_fdlimit;  ///< The maximum number of FDs this thread can open
	scap_userinfo m_user; ///< user infos
	scap_userinfo m_loginuser; ///< loginuser infos (auid)
	scap_groupinfo m_group; ///< group infos
	uint64_t m_cap_permitted; ///< permitted capabilities
	uint64_t m_cap_effective; ///< effective capabilities
	uint64_t m_cap_inheritable; ///< inheritable capabilities
	uint64_t m_exe_ino; ///< executable inode ino
	uint64_t m_exe_ino_ctime; ///< executable inode ctime (last status change time)
	uint64_t m_exe_ino_mtime; ///< executable inode mtime (last modification time)
	uint64_t m_exe_ino_ctime_duration_clone_ts; ///< duration in ns between executable inode ctime (last status change time) and clone_ts
	uint64_t m_exe_ino_ctime_duration_pidns_start; ///< duration in ns between pidns start ts and executable inode ctime (last status change time) if pidns start predates ctime
	uint64_t m_nchilds; ///< When this is 0 the process can be deleted
	uint32_t m_vmsize_kb; ///< total virtual memory (as kb).
	uint32_t m_vmrss_kb; ///< resident non-swapped memory (as kb).
	uint32_t m_vmswap_kb; ///< swapped memory (as kb).
	uint64_t m_pfmajor; ///< number of major page faults since start.
	uint64_t m_pfminor; ///< number of minor page faults since start.
	int64_t m_vtid;  ///< The virtual id of this thread.
	int64_t m_vpid; ///< The virtual id of the process containing this thread. In single thread threads, this is equal to vtid.
	int64_t m_vpgid; // The virtual process group id, as seen from its pid namespace
	uint64_t m_pidns_init_start_ts; ///<The pid_namespace init task (child_reaper) start_time ts.
	std::string m_root;
	size_t m_program_hash; ///< Unique hash of the current program
	size_t m_program_hash_scripts;  ///< Unique hash of the current program, including arguments for scripting programs (like python or ruby)
	int32_t m_tty; ///< Number of controlling terminal
	std::shared_ptr<thread_group_info> m_tginfo;
	std::list<std::weak_ptr<sinsp_threadinfo>> m_children;


	// In some cases, a threadinfo has a category that identifies
	// why it was run. Descriptions:
	// CAT_NONE: no specific category
	// CAT_CONTAINER: a process run in a container and *not* any
	//                of the following more specific categories.
	// CAT_HEALTHCHECK: part of a container healthcheck
	// CAT_LIVENESS_PROBE: part of a k8s liveness probe
	// CAT_READINESS_PROBE: part of a k8s readiness probe
	enum command_category {
		CAT_NONE = 0,
		CAT_CONTAINER,
		CAT_HEALTHCHECK,
		CAT_LIVENESS_PROBE,
		CAT_READINESS_PROBE
	};

	command_category m_category;

	//
	// State for multi-event processing
	//
	int64_t m_lastevent_fd; ///< The FD os the last event used by this thread.
	uint64_t m_lastevent_ts; ///< timestamp of the last event for this thread.
	uint64_t m_prevevent_ts; ///< timestamp of the event before the last for this thread.
	uint64_t m_lastaccess_ts; ///< The last time this thread was looked up. Used when cleaning up the table.
	uint64_t m_clone_ts; ///< When the clone that started this process happened.

	//
	// Parser for the user events. Public so that filter fields can access it
	//
	sinsp_tracerparser* m_tracer_parser;

	size_t args_len() const;
	size_t env_len() const;
	size_t cgroups_len() const;

	void args_to_iovec(struct iovec **iov, int *iovcnt,
			   std::string &rem) const;

	void env_to_iovec(struct iovec **iov, int *iovcnt,
			  std::string &rem) const;

	void cgroups_to_iovec(struct iovec **iov, int *iovcnt,
			      std::string &rem, const cgroups_t& cgroups) const;

	//
	// State for filtering
	//
	uint64_t m_last_latency_entertime;
	uint64_t m_latency;

	//
	// Global state
	//
	sinsp *m_inspector;

public: // types required for use in sets
	struct hasher {
		size_t operator()(sinsp_threadinfo* tinfo) const
		{
			return tinfo->get_main_thread()->m_program_hash;
		}
	};

	struct comparer {
		size_t operator()(sinsp_threadinfo* lhs, sinsp_threadinfo* rhs) const
		{
			return lhs->get_main_thread()->m_program_hash == rhs->get_main_thread()->m_program_hash;
		}
	};

VISIBILITY_PROTECTED
	/* Note that `fd_table` should be shared with the main thread only if `PPM_CL_CLONE_FILES`
	 * is specified. Today we always specify `PPM_CL_CLONE_FILES` for all threads.
	 */
	inline sinsp_fdtable* get_fd_table()
	{
		if(!(m_flags & PPM_CL_CLONE_FILES))
		{
			return &m_fdtable;
		}
		else
		{
			sinsp_threadinfo* root = get_main_thread();
			return (root == nullptr) ? nullptr : &(root->m_fdtable);
		}
	}

#ifndef _WIN32
	inline const sinsp_fdtable* get_fd_table() const
	{
		if(!(m_flags & PPM_CL_CLONE_FILES))
		{
			return &m_fdtable;
		}
		else
		{
			sinsp_threadinfo* root = get_main_thread();
			return (root == nullptr) ? nullptr : &(root->m_fdtable);
		}
	}
#endif

public:
VISIBILITY_PRIVATE
	void init();
	// return true if, based on the current inspector filter, this thread should be kept
	void init(scap_threadinfo* pi);
	void fix_sockets_coming_from_proc();
	sinsp_fdinfo_t* add_fd(int64_t fd, sinsp_fdinfo_t *fdinfo);
	void add_fd_from_scap(scap_fdinfo *fdinfo, OUT sinsp_fdinfo_t *res);
	void remove_fd(int64_t fd);
	void set_cwd(const char *cwd, uint32_t cwdlen);
	sinsp_threadinfo* get_cwd_root();
	void set_args(const char* args, size_t len);
	void set_env(const char* env, size_t len);
	bool set_env_from_proc();
	void set_cgroups(const char* cgroups, size_t len);
	bool is_lastevent_data_valid();
	inline void set_lastevent_data_validity(bool isvalid)
	{
		if(isvalid)
		{
			m_lastevent_cpuid = (uint16_t)1;
		}
		else
		{
			m_lastevent_cpuid = (uint16_t) - 1;
		}
	}
	void allocate_private_state();
	void compute_program_hash();
	std::shared_ptr<sinsp_threadinfo> lookup_thread() const;

	size_t strvec_len(const std::vector<std::string> &strs) const;
	void strvec_to_iovec(const std::vector<std::string> &strs,
			     struct iovec **iov, int *iovcnt,
			     std::string &rem) const;

	void add_to_iovec(const std::string &str,
			  const bool include_trailing_null,
			  struct iovec &iov,
			  uint32_t &alen,
			  std::string &rem) const;

	void fd_to_scap(scap_fdinfo *dst, sinsp_fdinfo_t* src);

	//  void push_fdop(sinsp_fdop* op);
	// the queue of recent fd operations
	//  std::deque<sinsp_fdop> m_last_fdop;

	//
	// Parameters that can't be accessed directly because they could be in the
	// parent thread info
	//
	sinsp_fdtable m_fdtable; // The fd table of this thread
	std::string m_cwd; // current working directory
	uint8_t* m_lastevent_data; // Used by some event parsers to store the last enter event
	std::vector<void*> m_private_state;

	uint16_t m_lastevent_type;
	uint16_t m_lastevent_cpuid;
	sinsp_evt::category m_lastevent_category;
	bool m_parent_loop_detected;
	blprogram* m_blprogram;

	friend class sinsp;
	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp_analyzer_parsers;
	friend class sinsp_evt;
	friend class sinsp_thread_manager;
	friend class sinsp_transaction_table;
	friend class sinsp_tracerparser;
	friend class lua_cbacks;
	friend class sinsp_baseliner;
};

/*@}*/

class threadinfo_map_t
{
public:
	typedef std::function<bool(const std::shared_ptr<sinsp_threadinfo>&)> shared_ptr_visitor_t;
	typedef std::function<bool(const sinsp_threadinfo&)> const_visitor_t;
	typedef std::function<bool(sinsp_threadinfo&)> visitor_t;
	typedef std::shared_ptr<sinsp_threadinfo> ptr_t;

	inline void put(ptr_t tinfo)
	{
		m_threads[tinfo->m_tid] = tinfo;
	}

	inline sinsp_threadinfo* get(uint64_t tid)
	{
		auto it = m_threads.find(tid);
		if (it == m_threads.end())
		{
			return  nullptr;
		}
		return it->second.get();
	}

	inline ptr_t get_ref(uint64_t tid)
	{
		auto it = m_threads.find(tid);
		if (it == m_threads.end())
		{
			return  nullptr;
		}
		return it->second;
	}

	inline void erase(uint64_t tid)
	{
		m_threads.erase(tid);
	}

	inline void clear()
	{
		m_threads.clear();
	}

	bool loop_shared_pointer(shared_ptr_visitor_t callback)
	{
		for (auto& it : m_threads)
		{
			if (!callback(it.second))
			{
				return false;
			}
		}
		return true;
	}

	bool const_loop(const_visitor_t callback) const
	{
		for (const auto& it : m_threads)
		{
			if (!callback(*it.second.get()))
			{
				return false;
			}
		}
		return true;
	}

	bool loop(visitor_t callback)
	{
		for (auto& it : m_threads)
		{
			if (!callback(*it.second.get()))
			{
				return false;
			}
		}
		return true;
	}

	inline size_t size() const
	{
		return m_threads.size();
	}

VISIBILITY_PROTECTED
	std::unordered_map<int64_t, ptr_t> m_threads;
};


///////////////////////////////////////////////////////////////////////////////
// Little class that manages the allocation of private state in the thread info class
///////////////////////////////////////////////////////////////////////////////
class sinsp_thread_privatestate_manager
{
public:
	//
	// The return value is the ID of the newly reserved memory area
	//
	uint32_t reserve(uint32_t size)
	{
		m_memory_sizes.push_back(size);
		return (uint32_t)m_memory_sizes.size() - 1;
	}

	uint32_t get_size()
	{
		return (uint32_t)m_memory_sizes.size();
	}

VISIBILITY_PRIVATE
	std::vector<uint32_t> m_memory_sizes;

	friend class sinsp_threadinfo;
};

///////////////////////////////////////////////////////////////////////////////
// This class manages the thread table
///////////////////////////////////////////////////////////////////////////////
class SINSP_PUBLIC sinsp_thread_manager
{
public:
	sinsp_thread_manager(sinsp* inspector);
	void clear();

	bool add_thread(sinsp_threadinfo *threadinfo, bool from_scap_proctable);
	sinsp_threadinfo* find_new_reaper(sinsp_threadinfo*);
	void remove_thread(int64_t tid, bool force);
	// Returns true if the table is actually scanned
	// NOTE: this is implemented in sinsp.cpp so we can inline it from there
	inline bool remove_inactive_threads();
	void remove_main_thread_fdtable(sinsp_threadinfo* main_thread);
	void fix_sockets_coming_from_proc();
	void reset_child_dependencies();
	void create_thread_dependencies_after_proc_scan();
	/*!
      \brief Look up a thread given its tid and return its information,
       and optionally go dig into proc if the thread is not in the thread table.

      \param tid the ID of the thread. In case of multi-thread processes,
       this corresponds to the PID.
      \param query_os_if_not_found if true, the library will search for this
       thread's information in proc, use the result to create a new thread
       entry, and return the new entry.

      \return the \ref sinsp_threadinfo object containing full thread information
       and state.

      \note if you are interested in a process' information, just give this
      function with the PID of the process.

      @throws a sinsp_exception containing the error string is thrown in case
       of failure.
    */

	threadinfo_map_t::ptr_t get_thread_ref(int64_t tid, bool query_os_if_not_found = false, bool lookup_only = true, bool main_thread=false);

	//
    // Note: lookup_only should be used when the query for the thread is made
    //       not as a consequence of an event for that thread arriving, but
    //       just for lookup reason. In that case, m_lastaccess_ts is not updated
    //       and m_last_tinfo is not set.
    //
    threadinfo_map_t::ptr_t find_thread(int64_t tid, bool lookup_only);


	void dump_threads_to_file(scap_dumper_t* dumper);

	uint32_t get_thread_count()
	{
		return (uint32_t)m_threadtable.size();
	}

	void update_statistics();

	threadinfo_map_t* get_threads()
	{
		return &m_threadtable;
	}

	std::set<uint16_t> m_server_ports;

	void set_max_thread_table_size(uint32_t value);

	int32_t get_m_n_proc_lookups() const { return m_n_proc_lookups; }
	int32_t get_m_n_main_thread_lookups() const { return m_n_main_thread_lookups; }
	uint64_t get_m_n_proc_lookups_duration_ns() const { return m_n_proc_lookups_duration_ns; }
	void reset_thread_counters() { m_n_proc_lookups = 0; m_n_main_thread_lookups = 0; m_n_proc_lookups_duration_ns = 0; }

	void set_m_max_n_proc_lookups(int32_t val) { m_max_n_proc_lookups = val; }
	void set_m_max_n_proc_socket_lookups(int32_t val) { m_max_n_proc_socket_lookups = val; }
	
	inline std::shared_ptr<thread_group_info> get_thread_group_info(int64_t pid) const
	{ 
		auto tgroup = m_thread_groups.find(pid);
		if(tgroup != m_thread_groups.end())
		{
			return tgroup->second;
		}
		return nullptr;
	}

	inline void set_thread_group_info(int64_t pid, const std::shared_ptr<thread_group_info>& tginfo)
	{ 
		/* It should be impossible to have a pid conflict...
		 * Right now we manage it but we could also remove it.
		 */
		auto ret = m_thread_groups.insert({pid, tginfo});
		if(!ret.second)
		{	
			m_thread_groups.erase(ret.first);
			m_thread_groups.insert({pid, tginfo});
		}
	}

VISIBILITY_PRIVATE
	void create_thread_dependencies(const std::shared_ptr<sinsp_threadinfo>& tinfo);
	inline void clear_thread_pointers(sinsp_threadinfo& threadinfo);
	void free_dump_fdinfos(std::vector<scap_fdinfo*>* fdinfos_to_free);
	void thread_to_scap(sinsp_threadinfo& tinfo, scap_threadinfo* sctinfo);

	sinsp* m_inspector;
	/* the key is the pid of the group, and the value is a shared pointer to the thread_group_info */
	std::unordered_map<int64_t, std::shared_ptr<thread_group_info>> m_thread_groups;
	threadinfo_map_t m_threadtable;
	int64_t m_last_tid;
	std::weak_ptr<sinsp_threadinfo> m_last_tinfo;
	uint64_t m_last_flush_time_ns;
	uint32_t m_n_drops;
	const uint32_t m_thread_table_absolute_max_size = 131072;
	uint32_t m_max_thread_table_size;
	int32_t m_n_proc_lookups = 0;
	uint64_t m_n_proc_lookups_duration_ns = 0;
	int32_t m_n_main_thread_lookups = 0;
	int32_t m_max_n_proc_lookups = -1;
	int32_t m_max_n_proc_socket_lookups = -1;

	INTERNAL_COUNTER(m_failed_lookups);
	INTERNAL_COUNTER(m_cached_lookups);
	INTERNAL_COUNTER(m_non_cached_lookups);
	INTERNAL_COUNTER(m_added_threads);
	INTERNAL_COUNTER(m_removed_threads);

	friend class sinsp_parser;
	friend class sinsp_analyzer;
	friend class sinsp;
	friend class sinsp_threadinfo;
	friend class sinsp_baseliner;
};
