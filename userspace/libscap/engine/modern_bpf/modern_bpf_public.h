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

#pragma once

#include <stdint.h>

#define MODERN_BPF_ENGINE "modern_bpf"
/* This will allow us to preserve the same memory footprint of the other 2 drivers (bpf, kmod) even if
 * they use a buffer for every CPU. This is because the `BPF_RINGBUF` is mapped twice both kernel and userspace-side,
 * so if we require a buffer of 8 MB the kernel will allocate 16 MB of memory under the hood.
 */
#define DEFAULT_BUFFER_FOR_EACH_CPU_PAIR 2

#ifdef __cplusplus
extern "C"
{
#endif

	struct scap_modern_bpf_engine_params
	{
		uint16_t cpus_for_each_buffer;	///< We will allocate a ring buffer every `cpus_for_each_buffer` CPUs. `0` is a special value and means a single ring buffer shared between all the CPUs.
		unsigned long buffer_bytes_dim; ///< Dimension of a ring buffer in bytes. The number of ring buffers allocated changes according to the `cpus_for_each_buffer` param. Please note: this buffer will be mapped twice both kernel and userspace-side, so pay attention to its size.
	};

#ifdef __cplusplus
};
#endif
