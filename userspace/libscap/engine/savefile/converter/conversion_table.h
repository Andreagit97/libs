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

#include <converter/converter_helpers.h>
#include <libscap/scap_const.h>
#include <unordered_map>

// todo!: we could insert this information in the event table because the index of the 2 tables are
// the same. The are pros and cons for this approach. drivers include the event table but don't need
// these conversion info. Moreover we could not compile this table at all if we don't need the
// savefile converter... On the other side it would be great to have all the information in one
// place. See `events_prog_names.h` in libpman or the `events_dimensions.h` in the modern ebpf. We
// could unify them all at a certain point.

static std::unordered_map<ppm_event_code, conversion_info> g_conversion_table = {
        {PPME_SYSCALL_OPEN_E, {.instr = {{C_ACTION_SKIP}}}},
        {PPME_SYSCALL_OPEN_X,
         {.desired_type = PPME_SYSCALL_OPEN,
          .valid_param_nums = {4, 6},
          .instr = {{C_FROM_OLD_EVENT | C_MOD_TO_32, 0},
                    {C_FROM_OLD_EVENT, 1},
                    {C_FROM_OLD_EVENT, 2},
                    {C_FROM_OLD_EVENT, 3},
                    {C_FROM_OLD_EVENT, 4},
                    {C_FROM_OLD_EVENT, 5}}}},
        {PPME_SYSCALL_BRK_1_E, {.instr = {{C_ACTION_SKIP}}}},
        {PPME_SYSCALL_BRK_1_X,
         {.desired_type = PPME_SYSCALL_BRK_4_X,
          .valid_param_nums = {1},
          .instr = {{C_FROM_OLD_EVENT, 0},
                    {C_FROM_DEFAULT, 1},
                    {C_FROM_DEFAULT, 2},
                    {C_FROM_DEFAULT, 3}}}},
        {PPME_SYSCALL_BRK_4_E, {.valid_param_nums = {1}, .instr = {{C_ACTION_STORAGE}}}},
        {PPME_SYSCALL_BRK_4_X,
         {.desired_type = PPME_SYSCALL_BRK,
          .valid_param_nums = {4},
          .instr = {{C_FROM_OLD_EVENT, 0},
                    {C_FROM_OLD_EVENT, 1},
                    {C_FROM_OLD_EVENT, 2},
                    {C_FROM_OLD_EVENT, 3},
                    {C_FROM_ENTER_EVENT, 0}}}},
        {PPME_SYSCALL_READ_E, {.valid_param_nums = {2}, .instr = {{C_ACTION_STORAGE}}}},
        {PPME_SYSCALL_READ_X,
         {.desired_type = PPME_SYSCALL_READ,
          .valid_param_nums = {2},
          .instr = {{C_FROM_OLD_EVENT | C_MOD_TO_32, 0},
                    {C_FROM_OLD_EVENT, 1},
                    {C_FROM_ENTER_EVENT | C_MOD_TO_32, 0},
                    {C_FROM_ENTER_EVENT, 1}}}},
};
