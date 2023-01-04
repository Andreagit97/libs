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

#include <stdbool.h>
#include <stdlib.h>
#include "../../../../driver/ppm_events_public.h"
#include "scap_open.h"
#include "scap.h"

struct scap;

struct modern_bpf_engine
{
	uint32_t m_possible_CPUs; /* Number of available CPUs, not online CPUs. */
	uint32_t m_allocated_buffers; /* Number of allocated ring buffers, according to the `m_buffer_mode` chosen */
	enum modern_bpf_buffer_mode m_buffer_mode; /* Ring buffer allocation mode */
	unsigned long m_retry_us; /* Microseconds to wait if all ring buffers are empty */
	char* m_lasterr; /* Last error caught by the engine */
	interesting_tp_set open_tp_set; /* Interesting tracepoints */
};
