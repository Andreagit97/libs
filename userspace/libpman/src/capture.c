/*
Copyright (C) 2022 The Falco Authors.

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

#include "state.h"
#include <scap.h>
#include <libpman.h>

int pman_enable_capture(bool *sc_set)
{
	/* We still need to understand the empty set case, should be handled by sinsp (?) */

	/* If we are interested in at least one syscall we need to enable sys_enter and sys_exit tracepoints. */
	bool attach_sys_tracepoints = false;
	int ret = 0;
	for(int syscall = 0; syscall < PPM_SC_SYSCALL_END; syscall++)
	{
		if(sc_set[syscall])
		{
			pman_mark_single_ppm_sc(syscall, true);
			if(!attach_sys_tracepoints)
			{
				ret = pman_attach_syscall_enter_dispatcher();
				ret = ret ?: pman_attach_syscall_exit_dispatcher();
				attach_sys_tracepoints = true;
			}
		}
	}

	/* If we have one of these syscalls we need to enable the dedicated logic */
#ifdef CAPTURE_SCHED_PROC_FORK
	if(sc_set[PPM_SC_CLONE] ||
	   sc_set[PPM_SC_CLONE3] ||
	   sc_set[PPM_SC_FORK] ||
	   sc_set[PPM_SC_VFORK])
	{
		ret = ret ?: pman_attach_sched_proc_fork();
	}
#endif

#ifdef CAPTURE_SCHED_PROC_EXEC
	if(sc_set[PPM_SC_EXECVE] ||
	   sc_set[PPM_SC_EXECVEAT])
	{
		ret = ret ?: pman_attach_sched_proc_exec();
	}
#endif

	/* Now we enable the required tracepoints */
	for(int tp = PPM_SC_TP_START; tp < PPM_SC_MAX; tp++)
	{
		if(sc_set[tp])
		{
			ret = ret ?: pman_update_single_program(tp, true);
		}
	}
	return ret;
}

int pman_disable_capture()
{
	/* If we fail at initialization time the BPF skeleton is not initialized */
	if(g_state.skel)
	{
		for(int syscall = 0; syscall < PPM_SC_SYSCALL_END; syscall++)
		{
			pman_mark_single_ppm_sc(syscall, false);
		}
		return pman_detach_all_programs();
	}
	return 0;
}

int pman_get_scap_stats(void *scap_stats_struct)
{
	struct scap_stats *stats = (struct scap_stats *)scap_stats_struct;
	char error_message[MAX_ERROR_MESSAGE_LEN];
	struct counter_map cnt_map;

	if(!stats)
	{
		pman_print_error("pointer to scap_stats is empty");
		return errno;
	}

	int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd <= 0)
	{
		pman_print_error("unable to get counter maps");
		return errno;
	}

	/* Not used in modern probe:
	 * - stats->n_drops_bug
	 * - stats->n_drops_pf
	 * - stats->n_preemptions
	 */

	/* We always take statistics from all the CPUs, even if some of them are not online.
	 * If the CPU is not online the counter map will be empty.
	 */
	for(int index = 0; index < g_state.n_possible_cpus; index++)
	{
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0)
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unbale to get the counter map for CPU %d", index);
			pman_print_error((const char *)error_message);
			goto clean_print_stats;
		}
		stats->n_evts += cnt_map.n_evts;
		stats->n_drops_buffer += cnt_map.n_drops_buffer;
		stats->n_drops_scratch_map += cnt_map.n_drops_max_event_size;
		stats->n_drops += (cnt_map.n_drops_buffer + cnt_map.n_drops_max_event_size);
	}
	return 0;

clean_print_stats:
	close(counter_maps_fd);
	return errno;
}

int pman_get_n_tracepoint_hit(long *n_events_per_cpu)
{
	char error_message[MAX_ERROR_MESSAGE_LEN];
	struct counter_map cnt_map;

	int counter_maps_fd = bpf_map__fd(g_state.skel->maps.counter_maps);
	if(counter_maps_fd <= 0)
	{
		pman_print_error("unable to get counter maps");
		return errno;
	}

	/* We always take statistics from all the CPUs, even if some of them are not online.
	 * If the CPU is not online the counter map will be empty.
	 */
	for(int index = 0; index < g_state.n_possible_cpus; index++)
	{
		if(bpf_map_lookup_elem(counter_maps_fd, &index, &cnt_map) < 0)
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "unbale to get the counter map for CPU %d", index);
			pman_print_error((const char *)error_message);
			goto clean_print_stats;
		}
		n_events_per_cpu[index] = cnt_map.n_evts;
	}
	return 0;

clean_print_stats:
	close(counter_maps_fd);
	return errno;
}
