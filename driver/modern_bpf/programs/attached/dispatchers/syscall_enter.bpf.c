/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/syscalls_dispatcher.h>

#ifdef CAPTURE_SOCKETCALL
#include <helpers/extract/extract_from_kernel.h>
#include <s390x-linux-gnu/asm/unistd_64.h>
#endif

/* From linux tree: /include/trace/events/syscall.h
 * TP_PROTO(struct pt_regs *regs, long id),
 */
SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter,
	     struct pt_regs *regs,
	     long syscall_id)
{
	/* The `syscall-id` can refer to both 64-bit and 32-bit architectures.
	 * Right now we filter only 64-bit syscalls, all the 32-bit syscalls
	 * will be dropped with `syscalls_dispatcher__check_32bit_syscalls`.
	 *
	 * If the syscall is not interesting we drop it.
	 */
	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id))
	{
		return 0;
	}

	/* Right now, drops all ia32 syscalls. */
	if(syscalls_dispatcher__check_32bit_syscalls())
	{
		return 0;
	}

#ifdef CAPTURE_SOCKETCALL
	if(syscall_id == __NR_socketcall)
	{
		int socketcall_id = (int)extract__syscall_argument(regs, 0);
		bpf_tail_call(ctx, &socketcall_enter_table, socketcall_id);
		return 0;
	}
#endif

	bpf_tail_call(ctx, &syscall_enter_tail_table, syscall_id);
	return 0;
}
