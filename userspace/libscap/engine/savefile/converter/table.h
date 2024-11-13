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

static std::unordered_map<ppm_event_code, conversion_info> g_conversion_table = {
        {PPME_SYSCALL_OPEN_E, {.desired_type = C_ACTION_SKIP, .valid_param_nums = {0, 3}}},
        {PPME_SYSCALL_OPEN_X,
         {.desired_type = PPME_SYSCALL_OPEN,
          .valid_param_nums = {4, 6},
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_OLD, 1},
                    {C_INSTR_FROM_OLD, 2},
                    {C_INSTR_FROM_OLD, 3},
                    {C_INSTR_FROM_OLD, 4},
                    {C_INSTR_FROM_OLD, 5}}}},
        {PPME_SYSCALL_BRK_1_E, {.desired_type = C_ACTION_SKIP, .valid_param_nums = {1}}},
        {PPME_SYSCALL_BRK_1_X,
         {.desired_type = PPME_SYSCALL_BRK_4_X,
          .valid_param_nums = {1},
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_DEFAULT, 1},
                    {C_INSTR_FROM_DEFAULT, 2},
                    {C_INSTR_FROM_DEFAULT, 3}}}},
        {PPME_SYSCALL_BRK_4_E, {.desired_type = C_ACTION_STORE, .valid_param_nums = {1}}},
        {PPME_SYSCALL_BRK_4_X,
         {.desired_type = PPME_SYSCALL_BRK,
          .valid_param_nums = {4},
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_OLD, 1},
                    {C_INSTR_FROM_OLD, 2},
                    {C_INSTR_FROM_OLD, 3},
                    {C_INSTR_FROM_ENTER, 0}}}},
        {PPME_SYSCALL_READ_E, {.desired_type = C_ACTION_STORE, .valid_param_nums = {2}}},
        {PPME_SYSCALL_READ_X,
         {.desired_type = PPME_SYSCALL_READ,
          .valid_param_nums = {2},
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_OLD, 1},
                    {C_INSTR_FROM_ENTER, 0},
                    {C_INSTR_FROM_ENTER, 1}}}},
};
