/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

SEC("tp_btf")
int BPF_PROG(t1_hotplug)
{
	// struct ringbuf_struct ringbuf;
	// if(!ringbuf__reserve_space(&ringbuf, ctx, HOTPLUG_E_SIZE))
	// {
	// 	return 0;
	// }

	// ringbuf__store_event_header(&ringbuf, PPME_CPU_HOTPLUG_E);

	// /*=============================== COLLECT PARAMETERS  ===========================*/

	// /* Parameter 1: cpu (type: PT_UINT32) */
	// u32 cpu_id = (u32)bpf_get_smp_processor_id();
	// ringbuf__store_u32(&ringbuf, flags);

	// /* Parameter 2: action (type: PT_UINT32) */
	// /* Right now we don't have actions we always send 0 */
	// ringbuf__store_u32(&ringbuf, 0);

	// /*=============================== COLLECT PARAMETERS  ===========================*/

	// ringbuf__submit_event(&ringbuf);

	return 0;
}
