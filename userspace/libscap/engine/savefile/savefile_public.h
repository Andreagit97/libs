// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
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
#include <libscap/scap_procs.h>
// At the moment we expose it for testing purposes. There are other alternatives:
// 1. We could create a custom small library for conversion but this would depend on scap or we need
// to manually duplicate some methods
// 2. We could put the conversion logic directly inside scap but it is used only by the savefile
// engine.
// 3. We could move the conversion logic directly in libsinsp.
#include <libscap/engine/savefile/converter/event_converter.h>

#define SAVEFILE_ENGINE "savefile"

#ifdef __cplusplus
extern "C" {
#endif
struct scap_platform;

struct scap_savefile_engine_params {
	int fd;                 ///< If non-zero, will be used instead of fname.
	const char* fname;      ///< The name of the file to open.
	uint64_t start_offset;  ///< Used to start reading a capture file from an arbitrary offset. This
	                        ///< is leveraged when opening merged files.
	uint32_t fbuffer_size;  ///< If non-zero, offline captures will read from file using a buffer of
	                        ///< this size.

	struct scap_platform* platform;
};

struct scap_platform* scap_savefile_alloc_platform(proc_entry_callback proc_callback,
                                                   void* proc_callback_context);

#ifdef __cplusplus
};
#endif
