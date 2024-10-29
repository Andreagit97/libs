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

#define C_ACTION_TERMINATE 0
#define C_ACTION_SKIP (1 << 0)
#define C_ACTION_STORAGE (1 << 1)
#define C_FROM_OLD_EVENT (1 << 2)
#define C_FROM_ENTER_EVENT (1 << 3)
#define C_FROM_DEFAULT (1 << 4)
#define C_MOD_TO_32 (1 << 5)

// Alternative way to define the struct:
// struct conversion_instruction {
// 	conversion_action action = C_ACTION_TERMINATE;
// 	conversion_source source = C_FROM_DEFAULT;
// 	conversion_modifier modifier = C_MOD_TO_32;
// 	uint8_t param_num = 0;
// };

struct conversion_instruction {
	uint16_t flags = 0;
	uint8_t param_num = 0;
};

struct conversion_info {
	uint16_t desired_type = 0;
	std::vector<uint8_t> valid_param_nums = {}; /* When we face a `0` we completed */
	conversion_instruction instr[32] = {};
};
