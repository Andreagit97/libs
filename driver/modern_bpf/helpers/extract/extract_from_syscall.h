/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#ifdef CAPTURE_SOCKETCALL

#include <helpers/interfaces/syscalls_dispatcher.h>
#include <syscall.h>

/* Do a compile-time check on socketcall syscall presence */
#ifndef __NR_socketcall
#error CAPTURE_SOCKETCALL defined but architecture does not support socketcall()
#endif

#endif


/* All the functions that are called in bpf to extract parameters
 * start with the `extract` prefix.
 */

/////////////////////////
// SYSCALL ARGUMENTS EXTRACION
////////////////////////

/**
 * @brief Extract a specific syscall argument
 *
 * @param regs pointer to the strcut where we find the arguments
 * @param idx index of the argument to extract
 * @return generic unsigned long value that can be a pointer to the arg
 * or directly the value, it depends on the type of arg.
 */
static __always_inline unsigned long extract__syscall_argument(struct pt_regs *regs, int idx)
{
	unsigned long arg;
	switch(idx)
	{
	case 0:
		arg = PT_REGS_PARM1_CORE_SYSCALL(regs);
		break;
	case 1:
		arg = PT_REGS_PARM2_CORE_SYSCALL(regs);
		break;
	case 2:
		arg = PT_REGS_PARM3_CORE_SYSCALL(regs);
		break;
	case 3:
		arg = PT_REGS_PARM4_CORE_SYSCALL(regs);
		break;
	case 4:
		arg = PT_REGS_PARM5_CORE_SYSCALL(regs);
		break;
	case 5:
		/* Not defined in libbpf, look at `definitions_helpers.h` */
		arg = PT_REGS_PARM6_CORE_SYSCALL(regs);
		break;
	default:
		arg = 0;
	}

	return arg;
}

/**
 * @brief Extract one ore more arguments related to a network / socket system call.
 *
 * This function takes into consideration whether the network system call has been
 * called directly (e.g. accept4) or through the socketcall system call multiplexer.
 * For the socketcall multiplexer, arguments are extracted from the second argument
 * of the socketcall system call.  See socketcall(2) for more information.
 *
 * @param argv Pointer to store up to @num arguments of size `unsigned long`
 * @param num Number of arguments to extract
 * @param regs Pointer to the struct pt_regs to access arguments and system call ID
 */
static __always_inline void extract__network_args(void *argv, int num, struct pt_regs *regs)
{
#ifdef CAPTURE_SOCKETCALL
	int id = syscalls_dispatcher__get_syscall_id(regs);
	if(id == __NR_socketcall)
	{
		unsigned long args_pointer = extract__syscall_argument(regs, 1);
		bpf_probe_read_user(argv, num * sizeof(unsigned long), (void*)args_pointer);
		return;
	}
#endif
	for (int i = 0; i < num; i++)
	{
		unsigned long *dst = (unsigned long *)argv;
		dst[i] = extract__syscall_argument(regs, i);
	}
}
