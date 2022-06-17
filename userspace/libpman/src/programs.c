#include "state.h"

/* Some notes about how a bpf program must be detached without unloading it:
 * https://lore.kernel.org/bpf/CAEf4BzZ8=dV0wvggAKnD64yXnhcXhdf1ovCT_LBd17RtJJXrdA@mail.gmail.com/T/
 */

/*=============================== ATTACH PROGRAMS ===============================*/
int pman_attach_syscall_enter_dispatcher()
{
	/* The program is already attached. */
	if(g_state.skel->links.dispatch_syscall_enter_events != NULL)
	{
		return 0;
	}

	g_state.skel->links.dispatch_syscall_enter_events = bpf_program__attach(g_state.skel->progs.dispatch_syscall_enter_events);
	if(!g_state.skel->links.dispatch_syscall_enter_events)
	{
		pman_print_error("failed to attach the 'dispatch_syscall_enter_events' program");
		return errno;
	}
	return 0;
}

int pman_attach_syscall_exit_dispatcher()
{
	/* The program is already attached. */
	if(g_state.skel->links.dispatch_syscall_exit_events != NULL)
	{
		return 0;
	}

	g_state.skel->links.dispatch_syscall_exit_events = bpf_program__attach(g_state.skel->progs.dispatch_syscall_exit_events);
	if(!g_state.skel->links.dispatch_syscall_exit_events)
	{
		pman_print_error("failed to attach the 'dispatch_syscall_exit_events' program");
		return errno;
	}
	return 0;
}

int pman_attach_sched_proc_exec()
{
	/* The program is already attached. */
	if(g_state.skel->links.sched_proc_exec != NULL)
	{
		return 0;
	}

	g_state.skel->links.sched_proc_exec = bpf_program__attach(g_state.skel->progs.sched_proc_exec);
	if(!g_state.skel->links.sched_proc_exec)
	{
		pman_print_error("failed to attach the 'sched_proc_exec' program");
		return errno;
	}
	return 0;
}

int pman_attach_sched_proc_fork()
{
	/* The program is already attached. */
	if(g_state.skel->links.sched_proc_fork != NULL)
	{
		return 0;
	}

	g_state.skel->links.sched_proc_fork = bpf_program__attach(g_state.skel->progs.sched_proc_fork);
	if(!g_state.skel->links.sched_proc_fork)
	{
		pman_print_error("failed to attach the 'sched_proc_fork' program");
		return errno;
	}
	return 0;
}

int pman_attach_all_programs()
{
	int err;
	err = pman_attach_syscall_enter_dispatcher();
	err = err ?: pman_attach_syscall_exit_dispatcher();
	err = err ?: pman_attach_sched_proc_exec();
	err = err ?: pman_attach_sched_proc_fork();
	/* add all other programs. */
	return err;
}

/*=============================== ATTACH PROGRAMS ===============================*/

/*=============================== DETACH PROGRAMS ===============================*/

int pman_detach_syscall_enter_dispatcher()
{
	if(g_state.skel->links.dispatch_syscall_enter_events && bpf_link__destroy(g_state.skel->links.dispatch_syscall_enter_events))
	{
		pman_print_error("failed to detach the 'dispatch_syscall_enter_events' program");
		return errno;
	}
	g_state.skel->links.dispatch_syscall_enter_events = NULL;
	return 0;
}

int pman_detach_syscall_exit_dispatcher()
{
	if(g_state.skel->links.dispatch_syscall_exit_events && bpf_link__destroy(g_state.skel->links.dispatch_syscall_exit_events))
	{
		pman_print_error("failed to detach the 'dispatch_syscall_exit_events' program");
		return errno;
	}
	g_state.skel->links.dispatch_syscall_exit_events = NULL;
	return 0;
}

int pman_detach_sched_proc_exec()
{
	if(g_state.skel->links.sched_proc_exec && bpf_link__destroy(g_state.skel->links.sched_proc_exec))
	{
		pman_print_error("failed to detach the 'sched_proc_exec' program");
		return errno;
	}
	g_state.skel->links.sched_proc_exec = NULL;
	return 0;
}

int pman_detach_sched_proc_fork()
{
	if(g_state.skel->links.sched_proc_fork && bpf_link__destroy(g_state.skel->links.sched_proc_fork))
	{
		pman_print_error("failed to detach the 'sched_proc_fork' program");
		return errno;
	}
	g_state.skel->links.sched_proc_fork = NULL;
	return 0;
}

int pman_detach_all_programs()
{
	int err;
	err = pman_detach_syscall_enter_dispatcher();
	err = err ?: pman_detach_syscall_exit_dispatcher();
	err = err ?: pman_detach_sched_proc_exec();
	err = err ?: pman_detach_sched_proc_fork();
	/* add all other programs. */
	return err;
}

/*=============================== DETACH PROGRAMS ===============================*/
