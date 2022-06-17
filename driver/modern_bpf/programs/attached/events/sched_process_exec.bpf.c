#include <helpers/interfaces/attached_programs.h>
#include <helpers/interfaces/variable_size_event.h>

/* TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
 * Taken from `/include/trace/events/sched.h`
 *
 *	struct sched_process_exec_raw_args
 * 	{
 *		struct task_struct *p;
 *		pid_t old_pid;
 *		struct linux_binprm *bprm;
 *	};
 */

SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_proc_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_EXECVE_19_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* We can also use the one provided by the ctx, we have to check that is the same!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
	struct task_struct *task = get_current_task();

	/* 1° Parameter: res (type: PT_ERRNO) */
	/* We set it to `0` since the execve is successfull*/
	auxmap__store_s64_param(auxmap, 0);

	unsigned long arg_start_pointer = 0;
	unsigned long arg_end_pointer = 0;

	/* Please note: these are the arguments of the process:
	 * `arg_start` points to the memory area where arguments start.
	 * We directly read charbufs from there, not pointers to charbufs!
	 * We will store charbufs directly from memory.
	 */
	READ_TASK_FIELD_INTO(&arg_start_pointer, task, mm, arg_start);
	READ_TASK_FIELD_INTO(&arg_end_pointer, task, mm, arg_end);

	unsigned long total_args_len = arg_end_pointer - arg_start_pointer;

	/* 2° Parameter: exe (type: PT_CHARBUF) */
	/* We need to extract the len of `exe` arg so we can undestand
	 * the overall length of the remaining args.
	 */
	u16 exe_arg_len = auxmap__store_charbuf_param(auxmap, arg_start_pointer);

	/* 3° Parameter: args (type: PT_CHARBUFARRAY) */
	/* Here we read all the array starting from the pointer to the first
	 * element. We could also read the array element per element but
	 * since we know the total len we read it as a `bytebuf`.
	 * The `\0` after every argument are preserved.
	 */
	auxmap__store_bytebuf_param(auxmap, arg_start_pointer + exe_arg_len, total_args_len - exe_arg_len);

	/* 4° Parameter: tid (type: PT_PID) */
	/* this is called `tid` but it is the `pid`. */
	s64 pid = (s64)extract__task_xid_nr(task, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, pid);

	/* 5° Parameter: pid (type: PT_PID) */
	/* this is called `pid` but it is the `tgid`. */
	s64 tgid = (s64)extract__task_xid_nr(task, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, tgid);

	/* 6° Parameter: ptid (type: PT_PID) */
	/* this is called `ptid` but it is the `pgid`. */
	s64 pgid = (s64)extract__task_xid_nr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, pgid);

	/* 7° Parameter: cwd (type: PT_CHARBUF) */
	/* leave the current working directory empty like in the old probe. */
	unsigned long cwd_pointer = 0;
	auxmap__store_empty_param(auxmap);

	/* 8° Parameter: fdlimit (type: PT_UINT64) */
	unsigned long fdlimit = 0;
	extract__fdlimit(task, &fdlimit);
	auxmap__store_u64_param(auxmap, fdlimit);

	/* 9° Parameter: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = 0;
	extract__pgft_maj(task, &pgft_maj);
	auxmap__store_u64_param(auxmap, pgft_maj);

	/* 10° Parameter: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = 0;
	extract__pgft_min(task, &pgft_min);
	auxmap__store_u64_param(auxmap, pgft_min);

	struct mm_struct *mm;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	/* 11° Parameter: vm_size (type: PT_UINT32) */
	u32 vm_size = extract__vm_size(mm);
	auxmap__store_u32_param(auxmap, vm_size);

	/* 12° Parameter: vm_rss (type: PT_UINT32) */
	u32 vm_rss = extract__vm_rss(mm);
	auxmap__store_u32_param(auxmap, vm_rss);

	/* 13° Parameter: vm_swap (type: PT_UINT32) */
	u32 vm_swap = extract__vm_swap(mm);
	auxmap__store_u32_param(auxmap, vm_swap);

	/* 14° Parameter: comm (type: PT_CHARBUF) */
	auxmap__store_charbuf_param(auxmap, (unsigned long)task->comm);

	/* 15° Parameter: cgroups (type: PT_CHARBUFARRAY) */
	/* Right now this is empty to reduce the complexity. */
	auxmap__store_empty_param(auxmap);

	unsigned long env_start_pointer = 0;
	unsigned long env_end_pointer = 0;

	/* Please note: these are the arguments of the process:
	 * `arg_start` points to the memory area where arguments start.
	 * We directly read charbufs from there, not pointers to charbufs!
	 * We will store charbufs directly from memory.
	 */
	READ_TASK_FIELD_INTO(&env_start_pointer, task, mm, env_start);
	READ_TASK_FIELD_INTO(&env_end_pointer, task, mm, env_end);

	unsigned long total_env_len = env_end_pointer - env_start_pointer;

	/* 16° Parameter: env (type: PT_CHARBUFARRAY) */
	auxmap__store_bytebuf_param(auxmap, env_start_pointer, total_env_len);

	/* 17° Parameter: tty (type: PT_INT32) */
	/// TODO: (PT_UINT32 not PT_INT32): this should be changed.
	u32 tty = exctract__tty(task);
	auxmap__store_s32_param(auxmap, (s32)tty);

	/* 18° Parameter: pgid (type: PT_PID) */
	/// TODO: still to implement! See what we do in the old probe.
	pid_t ptid = 0;
	auxmap__store_s64_param(auxmap, (s64)ptid);

	/* 19° Parameter: loginuid (type: PT_INT32) */
	/// TODO: (PT_UINT32 not PT_INT32): this should be changed.
	u32 loginuid;
	extract__loginuid(task, &loginuid);
	auxmap__store_s32_param(auxmap, (s32)loginuid);

	/* 20° Parameter: flags (type: PT_FLAGS32) */
	/// TODO: we still have to manage `exe_writable` flag.
	u32 flags = 0;
	auxmap__store_u32_param(auxmap, flags);

	/* 21° Parameter: cap_inheritable (type: PT_UINT64) */
	unsigned long cap_inheritable = extract__capability(task, EXTRACT_CAP_INHERITABLE);
	auxmap__store_u64_param(auxmap, cap_inheritable);

	/* 22° Parameter: cap_permitted (type: PT_UINT64) */
	unsigned long cap_permitted = extract__capability(task, EXTRACT_CAP_PERMITTED);
	auxmap__store_u64_param(auxmap, cap_permitted);

	/* 23° Parameter: cap_effective (type: PT_UINT64) */
	unsigned long cap_effective = extract__capability(task, EXTRACT_CAP_EFFECTIVE);
	auxmap__store_u64_param(auxmap, cap_effective);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}