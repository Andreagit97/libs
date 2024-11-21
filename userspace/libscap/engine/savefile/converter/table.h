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

#include <converter/types.h>
#include <libscap/scap_const.h>
#include <driver/ppm_events_public.h>

#include <unordered_map>

static std::unordered_map<conversion_key, conversion_info> g_conversion_table = {
        ////////////////////////////
        // OPEN
        ////////////////////////////
        {{PPME_SYSCALL_OPEN_E, 0}, {.action = C_ACTION_SKIP}},
        // We added 3 parameters for the TOCTOU mitigation.
        {{PPME_SYSCALL_OPEN_E, 3}, {.action = C_ACTION_SKIP}},
        // We added 2 parameters `dev` and `ino`
        {{PPME_SYSCALL_OPEN_X, 4},
         {.action = C_ACTION_ADD_PARAMS,
          .instr = {{C_INSTR_FROM_DEFAULT, 4}, {C_INSTR_FROM_DEFAULT, 5}}}},
        ////////////////////////////
        // BRK
        ////////////////////////////
        // Is useless to convert it to `PPME_SYSCALL_BRK_4_E` because we will just add a 0
        // parameter. The parameters of the 2 events are not the same.
        {{PPME_SYSCALL_BRK_1_E, 1}, {.action = C_ACTION_SKIP}},
        {{PPME_SYSCALL_BRK_1_X, 1},
         {.action = C_ACTION_CHANGE_TYPE,
          .desired_type = PPME_SYSCALL_BRK_4_X,
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_DEFAULT, 1},
                    {C_INSTR_FROM_DEFAULT, 2},
                    {C_INSTR_FROM_DEFAULT, 3}}}},
        {{PPME_SYSCALL_BRK_4_E, 1}, {.action = C_ACTION_STORE}},
        {{PPME_SYSCALL_BRK_4_X, 4},
         {.action = C_ACTION_ADD_PARAMS, .instr = {{C_INSTR_FROM_ENTER, 0}}}},
        ////////////////////////////
        // READ
        ////////////////////////////
        {{PPME_SYSCALL_READ_E, 2}, {.action = C_ACTION_STORE}},
        {{PPME_SYSCALL_READ_X, 2},
         {.action = C_ACTION_ADD_PARAMS,
          .instr = {{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}}}},
        ////////////////////////////
        // PREAD
        ////////////////////////////
        {{PPME_SYSCALL_PREAD_E, 3}, {.action = C_ACTION_STORE}},
        {{PPME_SYSCALL_PREAD_X, 2},
         {.action = C_ACTION_ADD_PARAMS,
          .instr = {{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}, {C_INSTR_FROM_ENTER, 2}}}},
};
