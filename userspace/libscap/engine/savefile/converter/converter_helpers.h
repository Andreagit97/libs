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

#include <converter/conversion_types.h>
#include <driver/ppm_events_public.h>

void change_event_type(scap_evt *evt, uint16_t event_type);

void copy_old_event(scap_evt *new_evt, scap_evt *evt_to_convert);

void change_param_len_from_s64_to_s32(scap_evt *e, uint8_t param_idx);

// todo!: evaluate if we need to improve the debug information
const char *get_event_name(ppm_event_code event_type);

char get_direction_char(ppm_event_code event_type);

conversion_result validate_nparams(scap_evt *evt, char *error, int num_valid_params, ...);

conversion_result return_error(scap_evt *evt, char *error);

uint16_t copy_first_n_lengths_and_header(scap_evt *new_evt,
                                         scap_evt *evt_to_convert,
                                         uint16_t num_lengths);

void fill_missing_lengths(scap_evt *new_evt, uint16_t *offset);

void copy_params(scap_evt *new_evt,
                 scap_evt *evt_to_convert,
                 uint16_t num_lengths,
                 uint16_t *offset);

void fill_missing_parameters_with_default(scap_evt *new_evt, uint16_t *offset);

void store_evt(uint64_t tid, scap_evt *evt);

scap_evt *retrieve_evt(uint64_t tid);

uint32_t get_param_len(scap_evt *evt, uint8_t num_param);

char *get_param_ptr(scap_evt *evt, uint8_t num_param);

void fill_missing_parameters(scap_evt *new_evt, uint16_t *offset, int num_args, ...);
