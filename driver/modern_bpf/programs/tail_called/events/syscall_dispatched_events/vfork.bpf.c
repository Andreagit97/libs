/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(vfork_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, VFORK_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_VFORK_20_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(vfork_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}
	auxmap__preload_event_header(auxmap, PPME_SYSCALL_VFORK_20_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_PID) */
	auxmap__store_s64_param(auxmap, ret);

	struct task_struct *task = get_current_task();

	/* We can extract `exe` (Parameter 2) and `args`(Parameter 3) only if the
	 * syscall doesn't fail. Otherwise, they will send empty parameters.
	 */
	if(ret >= 0)
	{
		unsigned long arg_start_pointer = 0;
		unsigned long arg_end_pointer = 0;

		/* Please note: these are the arguments of the process, not the
		 * argument with which we call the `clone` syscall.
		 * `arg_start` points to the memory area where arguments start.
		 * We directly read charbufs from there, not pointers to charbufs!
		 * We will store charbufs directly from memory.
		 */
		READ_TASK_FIELD_INTO(&arg_start_pointer, task, mm, arg_start);
		READ_TASK_FIELD_INTO(&arg_end_pointer, task, mm, arg_end);

		unsigned long total_args_len = arg_end_pointer - arg_start_pointer;

		/* Parameter 2: exe (type: PT_CHARBUF) */
		/* We need to extract the len of `exe` arg so we can undestand
		 * the overall length of the remaining args.
		 */
		u16 exe_arg_len = auxmap__store_charbuf_param(auxmap, arg_start_pointer, MAX_PROC_EXE, USER);

		/* Parameter 3: args (type: PT_CHARBUFARRAY) */
		/* Here we read all the array starting from the pointer to the first
		 * element. We could also read the array element per element but
		 * since we know the total len we read it as a `bytebuf`.
		 * The `\0` after every argument are preserved.
		 */
		auxmap__store_bytebuf_param(auxmap, arg_start_pointer + exe_arg_len, (total_args_len - exe_arg_len) & (MAX_PROC_ARG_ENV - 1), USER);
	}
	else
	{
		/* Parameter 2: exe (type: PT_CHARBUF) */
		auxmap__store_empty_param(auxmap);

		/* Parameter 3: args (type: PT_CHARBUFARRAY) */
		auxmap__store_empty_param(auxmap);
	}

	/* Parameter 4: tid (type: PT_PID) */
	s64 pid = (s64)extract__task_xid_nr(task, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, pid);

	/* Parameter 5: pid (type: PT_PID) */
	/* this is called `pid` but it is the `tgid`. */
	s64 tgid = (s64)extract__task_xid_nr(task, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, tgid);

	/* Parameter 6: ptid (type: PT_PID) */
	s64 ptid = (s64)extract__task_xid_nr(task, PIDTYPE_PGID);
	auxmap__store_s64_param(auxmap, ptid);

	/* Parameter 7: cwd (type: PT_CHARBUF) */
	/// TODO: right now we leave the current working directory empty like in the old probe.
	auxmap__store_empty_param(auxmap);

	/* Parameter 8: fdlimit (type: PT_UINT64) */
	unsigned long fdlimit = 0;
	extract__fdlimit(task, &fdlimit);
	auxmap__store_u64_param(auxmap, fdlimit);

	/* Parameter 9: pgft_maj (type: PT_UINT64) */
	unsigned long pgft_maj = 0;
	extract__pgft_maj(task, &pgft_maj);
	auxmap__store_u64_param(auxmap, pgft_maj);

	/* Parameter 10: pgft_min (type: PT_UINT64) */
	unsigned long pgft_min = 0;
	extract__pgft_min(task, &pgft_min);
	auxmap__store_u64_param(auxmap, pgft_min);

	struct mm_struct *mm;
	READ_TASK_FIELD_INTO(&mm, task, mm);

	/* Parameter 11: vm_size (type: PT_UINT32) */
	u32 vm_size = extract__vm_size(mm);
	auxmap__store_u32_param(auxmap, vm_size);

	/* Parameter 12: vm_rss (type: PT_UINT32) */
	u32 vm_rss = extract__vm_rss(mm);
	auxmap__store_u32_param(auxmap, vm_rss);

	/* Parameter 13: vm_swap (type: PT_UINT32) */
	u32 vm_swap = extract__vm_swap(mm);
	auxmap__store_u32_param(auxmap, vm_swap);

	/* Parameter 14: comm (type: PT_CHARBUF) */
	auxmap__store_charbuf_param(auxmap, (unsigned long)task->comm, TASK_COMM_LEN, KERNEL);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* We have to split here the bpf program, otherwise, it is too large
	 * for the verifier (limit 1000000 instructions).
	 */
	bpf_tail_call(ctx, &extra_event_prog_tail_table, T1_VFORK_X);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t1_vfork_x,
	     struct pt_regs *regs,
	     long ret)
{

/* We already catch the vfork child event with our `sched_process_fork` tracepoint,
 * for this reason we don't need also this instrumentation. Please note that we use
 * the aforementioned tracepoint only for the child event but we need to catch also
 * the father event or the failure case, for this reason we check the `ret==0`
 */
#ifdef CAPTURE_SCHED_PROC_FORK
	if(ret == 0)
	{
		return 0;
	}
#endif

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct task_struct *task = get_current_task();

	/* Parameter 15: cgroups (type: PT_CHARBUFARRAY) */
	auxmap__store_cgroups_param(auxmap, task);

	/* Parameter 16: flags (type: PT_FLAGS32) */
	/* In `fork`/`vfork` we don't have `flags` from syscall arguments. */
	u32 flags = 0;
	auxmap__store_u32_param(auxmap, (u32)extract__clone_flags(task, flags));

	/* Parameter 17: uid (type: PT_UINT32) */
	u32 euid = 0;
	extract__euid(task, &euid);
	auxmap__store_u32_param(auxmap, euid);

	/* Parameter 18: gid (type: PT_UINT32) */
	u32 egid = 0;
	extract__euid(task, &egid);
	auxmap__store_u32_param(auxmap, egid);

	/* Parameter 19: vtid (type: PT_PID) */
	pid_t vtid = extract__task_xid_vnr(task, PIDTYPE_PID);
	auxmap__store_s64_param(auxmap, (s64)vtid);

	/* Parameter 20: vpid (type: PT_PID) */
	pid_t vpid = extract__task_xid_vnr(task, PIDTYPE_TGID);
	auxmap__store_s64_param(auxmap, (s64)vpid);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* We have to split here the bpf program, otherwise, it is too large
	 * for the verifier (limit 1000000 instructions).
	 */
	bpf_tail_call(ctx, &extra_event_prog_tail_table, T2_VFORK_X);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(t2_vfork_x,
	     struct pt_regs *regs,
	     long ret)
{

	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	struct task_struct *task = get_current_task();

	/* Parameter 21: pid_namespace init task start_time monotonic time in ns (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, (u64)extract__task_pidns_start_time(task, PIDTYPE_TGID));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);
	return 0;
}

/*=============================== EXIT EVENT ===========================*/
