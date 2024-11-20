// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <vector>
#include <cstdint>

// Conversion instructions
#define C_NO_INSTR 0            // This should be never called
#define C_INSTR_FROM_OLD 1      // Take the parameter from the old event
#define C_INSTR_FROM_ENTER 2    // Take the parameter from the enter event
#define C_INSTR_FROM_DEFAULT 3  // Generate the default parameter

// Max number of parameters we want to validate
#define MAX_INSTR_CONVERSION 32

// Conversion actions
//
// Action use the same value space of `ppm_event_codes` so we use numbers that we will never reach
// just to avoid another field in the conversion_info struct
// #define C_ACTION_SKIP (1 << 16) - 1
// #define C_ACTION_STORE (1 << 16) - 2
// #define C_ACTION_FILL (1 << 16) - 3

// Conversion actions
enum conversion_action {
	C_ACTION_UNKNOWN = 0,
	C_ACTION_SKIP,
	C_ACTION_STORE,
	C_ACTION_FILL,
	C_ACTION_CHANGE_TYPE,
};

struct conversion_instruction {
	uint8_t flags = 0;
	uint8_t param_num = 0;
};

struct conversion_info {
	uint8_t action = 0;
	uint16_t desired_type = 0;  // This is need only when the action is `C_ACTION_CHANGE_TYPE`
	std::vector<uint8_t> valid_param_nums = {};  // When we face a `0` we completed
	std::vector<conversion_instruction> instr = {};
};
