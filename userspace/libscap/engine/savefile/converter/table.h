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
        // Open initially had 0 parameters than 3 for the TOCTOU mitigation.
        // All 3 parameters don't add additional info at the exit event so we can skip the whole
        // event.
        {PPME_SYSCALL_OPEN_E, {.action = C_ACTION_SKIP, .valid_param_nums = {0, 3}}},
        // Initially 4 then we added 2 `dev` and `ino`
        {PPME_SYSCALL_OPEN_X,
         {.action = C_ACTION_FILL,
          .valid_param_nums = {4, 6},
          // we could avoid the `C_INSTR_FROM_OLD` if we would be able to use designated
          // initializers
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_OLD, 1},
                    {C_INSTR_FROM_OLD, 2},
                    {C_INSTR_FROM_OLD, 3},
                    {C_INSTR_FROM_OLD, 4},
                    {C_INSTR_FROM_OLD, 5}}}},
        // The first parameter here was `size` but we don't need it anymore
        {PPME_SYSCALL_BRK_1_E, {.action = C_ACTION_SKIP, .valid_param_nums = {1}}},
        // When we switched from `PPME_SYSCALL_BRK_1_X` to `PPME_SYSCALL_BRK_4_X` we added 3
        // parameters, we cannot recover them from the scap-file so we need to fill them with the
        // default value.
        {PPME_SYSCALL_BRK_1_X,
         {.action = C_ACTION_CHANGE_TYPE,
          .desired_type = PPME_SYSCALL_BRK_4_X,
          .valid_param_nums = {1},
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_DEFAULT, 1},
                    {C_INSTR_FROM_DEFAULT, 2},
                    {C_INSTR_FROM_DEFAULT, 3}}}},
        {PPME_SYSCALL_BRK_4_E, {.action = C_ACTION_STORE, .valid_param_nums = {1}}},
        {PPME_SYSCALL_BRK_4_X,
         {.action = C_ACTION_FILL,
          .valid_param_nums = {4, 5},
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_OLD, 1},
                    {C_INSTR_FROM_OLD, 2},
                    {C_INSTR_FROM_OLD, 3},
                    {C_INSTR_FROM_ENTER, 0}}}},

        {PPME_SYSCALL_READ_E, {.action = C_ACTION_STORE, .valid_param_nums = {2}}},
        {PPME_SYSCALL_READ_X,
         {.action = C_ACTION_FILL,
          .valid_param_nums = {2, 4},
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_OLD, 1},
                    {C_INSTR_FROM_ENTER, 0},
                    {C_INSTR_FROM_ENTER, 1}}}},
        {PPME_SYSCALL_PREAD_E, {.action = C_ACTION_STORE, .valid_param_nums = {2}}},
        {PPME_SYSCALL_PREAD_X,
         {.action = C_ACTION_FILL,
          .valid_param_nums = {2, 4},
          .instr = {{C_INSTR_FROM_OLD, 0},
                    {C_INSTR_FROM_OLD, 1},
                    {C_INSTR_FROM_ENTER, 0},
                    {C_INSTR_FROM_ENTER, 1}}}},
};
