/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/common.h>
#include <shared_definitions/struct_definitions.h>
#include <driver/ppm_events_public.h>
#include <driver/driver_config.h>

/*=============================== BPF READ-ONLY GLOBAL VARIABLES ===============================*/

/* The `volatile` qualifier is necessary to make sure Clang doesn't optimize away the read-only
 * global variables, ignoring user-space provided value. Without it, Clang is free to
 * just assume 0 and remove the variable completely.
 *
 * These read-only global variables need to be set before BPF skeleton is loaded into the
 * kernel by the user-space. These maps don't change after loading phase. They are initialized by
 * userspace before loading phase and they can no longer be modified neither
 * on the userspace-side nor on the bpf-side.
 */

/**
 * @brief Take as input the `ppm_event_type` enum and return the number
 * of parameters for that event.
 */
__weak const volatile uint8_t g_event_params_table[PPM_EVENT_MAX];

/**
 * @brief Actual probe API version
 */
__weak const volatile uint64_t probe_api_ver = PPM_API_CURRENT_VERSION;

/**
 * @brief Actual probe schema version
 */
__weak const volatile uint64_t probe_schema_var = PPM_SCHEMA_CURRENT_VERSION;

/**
 * @brief Ring buffer configuration: `INTERNAL_PER_CPU_BUFFER` is the default choice.
 *  `INTERNAL_PER_CPU_BUFFER` means that we allocate a ring buffer for every CPU.
 */
__weak const volatile uint8_t ring_buffer_mode = INTERNAL_PER_CPU_BUFFER;

/*=============================== BPF READ-ONLY GLOBAL VARIABLES ===============================*/

/*=============================== BPF GLOBAL VARIABLES ===============================*/

/**
 * @brief Given the syscall id on 64-bit-architectures returns if
 * the syscall must be filtered out according to the simple consumer logic.
 */
__weak bool g_64bit_interesting_syscalls_table[SYSCALL_TABLE_SIZE];

/**
 * @brief Global capture settings shared between userspace and
 * bpf programs.
 */
__weak struct capture_settings g_settings;

/*=============================== BPF GLOBAL VARIABLES ===============================*/

/*=============================== BPF_MAP_TYPE_PROG_ARRAY ===============================*/

/**
 * @brief This tail table is used by the syscall_enter_disptacher.
 * Given the syscall_id, it calls the right bpf program to manage
 * the syscall enter event.
 */
struct
{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, SYSCALL_TABLE_SIZE);
	__type(key, u32);
	__type(value, u32);
} syscall_enter_tail_table __weak SEC(".maps");

/**
 * @brief This tail table is used by the syscall_exit_disptacher.
 * Given the syscall_id, it calls the right bpf program to manage
 * the syscall exit event.
 */
struct
{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, SYSCALL_TABLE_SIZE);
	__type(key, u32);
	__type(value, u32);
} syscall_exit_tail_table __weak SEC(".maps");

/**
 * @brief This tail table is used when a bpf program needs another program
 * to complete its execution flow. This table could be used both by
 * programs directly attached in the kernel (like page_faults,
 * context_switch, ...) and by syscall_events (like
 * ppme_syscall_execveat_x, ...).
 * Given a predefined tail-code (`extra_event_prog_code`), it calls
 * the right bpf program.
 */
struct
{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, TAIL_EXTRA_EVENT_PROG_MAX);
	__type(key, u32);
	__type(value, u32);
} extra_event_prog_tail_table __weak SEC(".maps");

/*=============================== BPF_MAP_TYPE_PROG_ARRAY ===============================*/

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

/* These maps have one entry for each CPU.
 *
 * PLEASE NOTE:
 * We cannot use `BPF_MAP_TYPE_PERCPU_ARRAY` since there is a limit on the maximum size
 * of the single array element. `BPF_MAP_TYPE_PERCPU_ARRAY` maps have just one entry that is
 * a per-cpu array. The problem is that the maximum size of the single element could be 32 KB
 * at maximum, while we need at least 128 KB, so an array-size of 128 KB * n_cpus.
 * For more info:
 * https://github.com/torvalds/linux/blob/09688c0166e76ce2fb85e86b9d99be8b0084cdf9/mm/percpu.c#L1756
 *
 */

/**
 * @brief For every CPU on the system we have an auxiliary
 * map where the event is temporally saved before being
 * pushed in the ringbuffer.
 */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct auxiliary_map);
} auxiliary_maps __weak SEC(".maps");

/**
 * @brief For every CPU on the system we have a counter
 * map where we store the number of events correctly pushed
 * and the number of events dropped.
 */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct counter_map);
} counter_maps __weak SEC(".maps");

/*=============================== BPF_MAP_TYPE_ARRAY ===============================*/

/*=============================== RINGBUF MAP ===============================*/

/* This map will be used only if the `ring_buffer_mode` is `INTERNAL_SINGLE_BUFFER`.
 * In all other cases we create it with a minimum dimension (2 KB) and we will never use it.
 * We need to create it even if it is unused, otherwise we cannot load correctly our BPF programs.
 */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MIN_SINGLE_BUFFER_DIM);
} single_ringbuffer __weak SEC(".maps");

/**
 * @brief We use this map to let the verifier understand the content of our array of maps (`ringbuf_maps`)
 */
struct ringbuf_map
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
};

/**
 * @brief This array of maps will be used if the `ring_buffer_mode` is `INTERNAL_PER_CPU_BUFFER`
 * or `INTERNAL_PAIRED_BUFFER`. `INTERNAL_PER_CPU_BUFFER` means that every CPU has an associated 
 * ring_buffer, while `INTERNAL_PAIRED_BUFFER` means that to every CPU pair corresponds a ring buffer.
 * In the case of `INTERNAL_SINGLE_BUFFER` we don't use this array of maps but we will use the
 * `single_ringbuffer` approach.
 */
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, u32);
	__type(value, u32);
	__array(values, struct ringbuf_map);
} ringbuf_maps __weak SEC(".maps");

/*=============================== RINGBUF MAP ===============================*/
