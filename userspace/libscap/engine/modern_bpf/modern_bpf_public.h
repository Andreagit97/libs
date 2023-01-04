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

/**
 * - `MODERN_PER_CPU_BUFFER`: we allocate a ring buffer for every possible CPU, so we will have an
 *   array of ring buffers.
 * - `MODERN_PAIRED_BUFFER`: we allocate a ring buffer for every possible CPU pair, also in this case
 *   we will have an array of ring buffers.
 * - `MODERN_SINGLE_BUFFER`: we allocate a unique ring buffer shared between all the CPUs
 */
enum modern_bpf_buffer_mode {
	MODERN_PER_CPU_BUFFER = 0,
	MODERN_PAIRED_BUFFER = 1,
	MODERN_SINGLE_BUFFER = 2,
};

/* Macro that should be used to translate the mode chosen by the user. */
#define MODERN_PER_CPU_BUFFER_NAME "per-cpu"
#define MODERN_PAIRED_BUFFER_NAME "paired"
#define MODERN_SINGLE_BUFFER_NAME "single"

extern const char* get_modern_bpf_buffer_mode_name(enum modern_bpf_buffer_mode mode);

#ifdef __cplusplus
extern "C"
{
#endif

	struct scap_modern_bpf_engine_params
	{
		enum modern_bpf_buffer_mode buffer_mode; ///< According to this mode we allocate a different number of ring buffers.
		unsigned long buffer_bytes_dim; ///< Dimension of a ring buffer in bytes. The number of ring buffers allocated changes according to the `buffer_mode`. Please note: this buffer will be mapped twice both kernel and userspace-side, so pay attention to its size.
	};

#ifdef __cplusplus
};
#endif
