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

// todo!: rename into converter_helpers

#include <driver/ppm_events_public.h>
#include <converter/conversion_types.h>
#include <converter/conversion_result.h>
#include <converter/conversion_table.h>
#include <converter/debug_macro.h>
#include <stdarg.h>
#include <cstdio>
#include <cassert>
#include <unordered_map>
#include <string>
#include <stdexcept>

static std::unordered_map<uint64_t, scap_evt *> evt_storage = {};

extern const struct ppm_event_info g_event_info[];

void change_event_type(scap_evt *evt, uint16_t event_type) {
	evt->type = event_type;
}

void copy_old_event(scap_evt *new_evt, scap_evt *evt_to_convert) {
	memcpy(new_evt, evt_to_convert, evt_to_convert->len);
	PRINT_MESSAGE("New copied event:\n");
	PRINT_EVENT(new_evt, PRINT_FULL);
}

// the first parameter of te event has `param_idx` == 0
void change_param_len_from_s64_to_s32(scap_evt *e, uint8_t param_idx) {
	uint16_t off_len = sizeof(scap_evt);
	uint16_t tot_len = 0;

	for(int i = 0; i < param_idx; i++) {
		uint16_t len = 0;
		memcpy(&len, (char *)e + off_len, sizeof(uint16_t));
		off_len += sizeof(uint16_t);
		tot_len += len;
	}

	// 16 bits are enough, see MAX_EVENT_SIZE
	uint16_t param_offset = sizeof(scap_evt) + sizeof(uint16_t) * e->nparams + tot_len;
	PRINT_MESSAGE(
	        "We need to change the dimension (64->32) of the param. Length array offset %d, "
	        "param offset in the event: %d\n",
	        off_len,
	        param_offset);

	int64_t old_param = 0;
	memcpy(&old_param, (char *)e + param_offset, sizeof(int64_t));
	PRINT_MESSAGE("Old param was: %ld.\n", old_param);

	int32_t new_param = (int32_t)old_param;
	memcpy((char *)e + param_offset, &new_param, sizeof(int32_t));
	PRINT_MESSAGE("New param is: %d.\n", new_param);

	memmove((char *)e + param_offset + sizeof(int32_t),
	        (char *)e + param_offset + sizeof(int64_t),
	        e->len - (param_offset + sizeof(int64_t)));

	// Store the new param len
	static uint16_t new_len = 4;
	memcpy((char *)e + off_len, &new_len, sizeof(uint16_t));

	// Store the new event len
	e->len -= sizeof(int32_t);
	PRINT_MESSAGE("New converted event\n");
	PRINT_EVENT(e, PRINT_FULL);
}

// todo!: evaluate if we need to improve the debug information
const char *get_event_name(ppm_event_code event_type) {
	const struct ppm_event_info *event_info = &g_event_info[event_type];
	return event_info->name;
}

char get_direction_char(ppm_event_code event_type) {
	if(event_type > PPME_SYSCALL_OPEN) {
		return ' ';
	}

	if(PPME_IS_ENTER(event_type)) {
		return 'E';
	} else {
		return 'X';
	}
}

conversion_result return_error(scap_evt *evt, char *error) {
	// This should never happen
	snprintf(error, SCAP_LASTERR_SIZE, "Reached unkown state for event '%d'.", evt->type);
	return CONVERSION_ERROR;
}

// returns the `offset` of the new event
uint16_t copy_first_n_lengths_and_header(scap_evt *new_evt,
                                         scap_evt *evt_to_convert,
                                         uint16_t num_lengths) {
	PRINT_MESSAGE("Event to convert:\n");
	PRINT_EVENT(evt_to_convert, PRINT_FULL);

	// We keep the header and the first n lengths.
	uint16_t offset = sizeof(scap_evt) + sizeof(uint16_t) * num_lengths;
	memcpy(new_evt, evt_to_convert, offset);

	PRINT_MESSAGE("Copy header and first '%d' lengths. Tmp new event:\n", num_lengths);
	PRINT_EVENT(new_evt, PRINT_HEADER_LENGTHS);
	return offset;
}

uint16_t copy_header(scap_evt *new_evt, scap_evt *evt_to_convert) {
	memcpy(new_evt, evt_to_convert, sizeof(scap_evt));
	return sizeof(scap_evt);
}

void fill_missing_lengths(scap_evt *new_evt, uint16_t *offset) {
	// Please ensure that `new_evt->type` is already the final type you want to obtain.
	// Otherwise we will access the wrong entry in the event table.
	const struct ppm_event_info *event_info = &(g_event_info[new_evt->type]);

	for(uint16_t i = new_evt->nparams; i < event_info->nparams; i++) {
		uint16_t len = scap_get_size_bytes_from_type(event_info->params[i].type);
		PRINT_MESSAGE("push len (%d) for param (%d, type: %d) at offest (%d)\n",
		              len,
		              i,
		              event_info->params[i].type,
		              *offset);
		memcpy((char *)new_evt + *offset, &len, sizeof(uint16_t));
		*offset += sizeof(uint16_t);
	}
}

void copy_params(scap_evt *new_evt,
                 scap_evt *evt_to_convert,
                 uint16_t num_lengths,
                 uint16_t *offset) {
	// This is where the params start inside the event to convert
	uint16_t offset_evt_to_convert = sizeof(scap_evt) + sizeof(uint16_t) * num_lengths;
	uint16_t len_to_copy = evt_to_convert->len - offset_evt_to_convert;

	memcpy((char *)new_evt + *offset, (char *)evt_to_convert + offset_evt_to_convert, len_to_copy);

	PRINT_MESSAGE(
	        "copy the rest of the event to convert (len: %d) in the new event at offest (%d)\n",
	        len_to_copy,
	        *offset);

	*offset += len_to_copy;
}

void fill_missing_parameters_with_default(scap_evt *new_evt, uint16_t *offset) {
	// Please ensure that `new_evt->type` is already the final type you want to obtain.
	// Otherwise we will access the wrong entry in the event table.
	const struct ppm_event_info *event_info = &(g_event_info[new_evt->type]);

	for(uint16_t i = new_evt->nparams; i < event_info->nparams; i++) {
		// todo!: Please note that at the moment `value` can be also NULL, we could turn it into ""
		// if necessary.
		char *value = scap_get_default_value_from_type(event_info->params[i].type);
		PRINT_MESSAGE("push param (%d, type: %d) at offest (%d)\n",
		              i,
		              event_info->params[i].type,
		              *offset);
		// if value is NULL, the len should be 0
		memcpy((char *)new_evt + *offset,
		       value,
		       scap_get_size_bytes_from_type(event_info->params[i].type));
		*offset += scap_get_size_bytes_from_type(event_info->params[i].type);
	}

	// Adjust the number of parameters
	new_evt->nparams = event_info->nparams;
	// Adjust the final length
	new_evt->len = *offset;

	PRINT_MESSAGE("Final event:\n");
	PRINT_EVENT(new_evt, PRINT_FULL);
}

void store_evt(uint64_t tid, scap_evt *evt) {
	// if there was a previous event for this tid, we can overwrite the pointer because it means we
	// don't need it anymore. We need to keep the enter event until we retrieve it in the
	// corresponding exit event, but if the same thread is doing another enter event it means the
	// previous syscall is already completed

	// todo!: use smart pointers.
	if(evt_storage.find(tid) != evt_storage.end()) {
		free(evt_storage[tid]);
	}

	scap_evt *tmp_evt = (scap_evt *)malloc(evt->len);
	memcpy(tmp_evt, evt, evt->len);
	evt_storage[tid] = tmp_evt;
}

scap_evt *retrieve_evt(uint64_t tid) {
	// todo! : we need to check that the type is the right one not just the tid
	if(evt_storage.find(tid) != evt_storage.end()) {
		return evt_storage[tid];
	}
	return nullptr;
}

void clear_storage() {
	for(auto it = evt_storage.begin(); it != evt_storage.end(); ++it) {
		free(it->second);
	}
	evt_storage.clear();
}

uint16_t get_param_len(scap_evt *evt, uint8_t num_param) {
	if(evt->nparams <= num_param) {
		std::string error = "Try to access len of param num '" + std::to_string(num_param) +
		                    "' for event " + get_event_name((ppm_event_code)evt->type) + "_" +
		                    get_direction_char((ppm_event_code)evt->type) +
		                    " (num parameters: " + std::to_string(evt->type) + ").";
		throw std::runtime_error(error);
	}

	// todo!: we need to manage LARGE_PAYLOAD events
	uint16_t off_len = sizeof(scap_evt) + sizeof(uint16_t) * num_param;
	uint16_t len = 0;
	memcpy(&len, (char *)evt + off_len, sizeof(uint16_t));
	return (uint32_t)len;
}

char *get_param_ptr(scap_evt *evt, uint8_t num_param) {
	if(evt->nparams <= num_param) {
		std::string error = "Try to access param num '" + std::to_string(num_param) +
		                    "' for event " + get_event_name((ppm_event_code)evt->type) + "_" +
		                    get_direction_char((ppm_event_code)evt->type) +
		                    " (num parameters: " + std::to_string(evt->type) + ").";
		throw std::runtime_error(error);
	}

	// todo!: we need to manage LARGE_PAYLOAD events
	char *ptr = (char *)evt + sizeof(scap_evt) + sizeof(uint16_t) * evt->nparams;
	uint16_t ptr_off = 0;
	for(auto i = 0; i < num_param; i++) {
		uint16_t len = 0;
		memcpy(&len, (char *)evt + sizeof(scap_evt) + sizeof(uint16_t) * i, sizeof(uint16_t));
		ptr_off += len;
	}

	return ptr + ptr_off;
}

void fill_missing_parameters(scap_evt *new_evt, uint16_t *offset, int num_args, ...) {
	// We should always receive pairs of arguments (param, len)
	if(num_args == 0 || num_args % 2 != 0) {
		std::string error = "Try to call the method with an odd number of arguments: " +
		                    std::to_string(num_args);
		throw std::runtime_error(error);
	}

	va_list args;
	va_start(args, num_args);

	for(int i = 0; i < num_args; i += 2) {
		uint16_t param_len = va_arg(args, int);
		char *get_param_ptr = va_arg(args, char *);

		memcpy((char *)new_evt + *offset, get_param_ptr, param_len);
		*offset += param_len;
	}
	va_end(args);

	// Adjust the number of parameters
	new_evt->nparams = g_event_info[new_evt->type].nparams;
	// Adjust the final length
	new_evt->len = *offset;

	PRINT_MESSAGE("Final event:\n");
	PRINT_EVENT(new_evt, PRINT_FULL);
}

conversion_result validate_nparams(scap_evt *evt,
                                   std::vector<uint8_t> &valid_param_nums,
                                   char *error) {
	// We skip the validation phase if the array is empty
	if(valid_param_nums.empty()) {
		return CONVERSION_CONTINUE;
	}

	for(const auto &valid_param : valid_param_nums) {
		if(evt->nparams == valid_param) {
			return CONVERSION_CONTINUE;
		}
	}

	snprintf(error,
	         SCAP_LASTERR_SIZE,
	         "Unknown number of parameters '%d' for event '%s_%c(num: %d)'.",
	         evt->nparams,
	         get_event_name((ppm_event_code)evt->type),
	         get_direction_char((ppm_event_code)evt->type),
	         evt->type);
	return CONVERSION_ERROR;
}

// This writes len + the param
void push_default_parameter(scap_evt *evt, uint16_t *params_offset, uint8_t param_num) {
	// Please ensure that `new_evt->type` is already the final type you want to obtain.
	// Otherwise we will access the wrong entry in the event table.
	const struct ppm_event_info *event_info = &(g_event_info[evt->type]);
	uint16_t len = scap_get_size_bytes_from_type(event_info->params[param_num].type);
	char *ptr = scap_get_default_value_from_type(event_info->params[param_num].type);
	uint16_t lens_offset = sizeof(scap_evt) + param_num * sizeof(uint16_t);

	PRINT_MESSAGE(
	        "push default param (%d, type: %d) with len (%d) at {params_offest (%d), "
	        "lens_offset (%d)}\n",
	        param_num,
	        event_info->params[param_num].type,
	        len,
	        *params_offset,
	        lens_offset);

	// If value is NULL, the len should be 0
	memcpy((char *)evt + *params_offset, ptr, len);
	*params_offset += len;
	memcpy((char *)evt + lens_offset, &len, sizeof(uint16_t));
}

void push_parameter(scap_evt *new_evt,
                    scap_evt *tmp_evt,
                    uint16_t *params_offset,
                    uint8_t param_num,
                    uint8_t evt_param_pos,
                    uint16_t flags) {
	uint16_t len = 0;
	char *ptr = 0;
	uint16_t lens_offset = sizeof(scap_evt) + param_num * sizeof(uint16_t);

	// Let's first see if we have a len modifier.
	if(flags & C_MOD_TO_32) {
		len = 4;
	} else {
		len = get_param_len(tmp_evt, evt_param_pos);
	}
	ptr = get_param_ptr(tmp_evt, evt_param_pos);

	PRINT_MESSAGE(
	        "push param (%d) with len (%d, modified %s) at {params_offest (%d), "
	        "lens_offset (%d)} from param (%d) in %s event\n",
	        param_num,
	        len,
	        flags & C_MOD_TO_32 ? "yes" : "no",
	        *params_offset,
	        lens_offset,
	        evt_param_pos,
	        flags & C_FROM_OLD_EVENT ? "old" : "enter");

	// todo!: At the moment we just convert from s64 to s32 so this code should be always ok, check
	// if this is the case.
	memcpy((char *)new_evt + *params_offset, ptr, len);
	*params_offset += len;
	memcpy((char *)new_evt + lens_offset, &len, sizeof(uint16_t));
}

conversion_result convert_event(scap_evt *new_evt,
                                scap_evt *evt_to_convert,
                                conversion_info *ci,
                                char *error) {
	// First we validate the number of parameters if necessary
	if(validate_nparams(evt_to_convert, ci->valid_param_nums, error) == CONVERSION_ERROR) {
		return CONVERSION_ERROR;
	}

	// Skip the convertion if needed
	if(ci->instr[0].flags & C_ACTION_SKIP) {
		return CONVERSION_SKIP;
	}

	// Store the event if needed
	if(ci->instr[0].flags & C_ACTION_STORAGE) {
		store_evt(evt_to_convert->tid, evt_to_convert);
		return CONVERSION_SKIP;
	}

	/////////////////////////////
	// Start the real conversion in all other cases
	/////////////////////////////

	// update the type and the number of parameters. We just need to update the final length at the
	// end.
	memcpy(new_evt, evt_to_convert, sizeof(scap_evt));
	new_evt->type = ci->desired_type;
	new_evt->nparams = g_event_info[new_evt->type].nparams;
	PRINT_MESSAGE("New event header (the len is still the old one):\n");
	PRINT_EVENT(new_evt, PRINT_HEADER);

	uint16_t params_offset = sizeof(scap_evt) + new_evt->nparams * sizeof(uint16_t);
	scap_evt *tmp_evt = NULL;
	uint32_t flags = 0;

	for(int i = 0; i < PPM_MAX_EVENT_PARAMS; i++) {
		flags = ci->instr[i].flags;
		if(flags == C_ACTION_TERMINATE) {
			// It was the last parameter we need to do nothing
			break;
		}

		// We shouldn't have modifiers so ` == C_FROM_DEFAULT` should be ok.
		if(flags == C_FROM_DEFAULT) {
			push_default_parameter(new_evt, &params_offset, i);
			continue;
		}

		if(flags & C_FROM_ENTER_EVENT) {
			tmp_evt = retrieve_evt(evt_to_convert->tid);
			if(!tmp_evt) {
				// If there is no the enter event because we dropped it in the capture or we come
				// here from another conversion (see the BRK_1 example) we get the default value.
				push_default_parameter(new_evt, &params_offset, i);
				continue;
			}
			// todo!: undestand if we can pretend this is an error or it is a normal situation.
			if(tmp_evt->type != evt_to_convert->type - 1) {
				snprintf(error,
				         SCAP_LASTERR_SIZE,
				         "The enter event for '%s_%c' is not the right one! Event found '%s_%c'.",
				         get_event_name((ppm_event_code)evt_to_convert->type),
				         get_direction_char((ppm_event_code)evt_to_convert->type),
				         get_event_name((ppm_event_code)tmp_evt->type),
				         get_direction_char((ppm_event_code)tmp_evt->type));
				return CONVERSION_ERROR;
			}

		} else if(flags & C_FROM_OLD_EVENT) {
			tmp_evt = evt_to_convert;
			if(tmp_evt->nparams <= i) {
				// If this is an old version we don't have the available parameters so we get the
				// default value (see OPEN_X example).
				push_default_parameter(new_evt, &params_offset, i);
				continue;
			}
		} else {
			snprintf(error,
			         SCAP_LASTERR_SIZE,
			         "Unknown instruction (flags: %d, param_num: %d).",
			         ci->instr[i].flags,
			         ci->instr[i].param_num);
			return CONVERSION_ERROR;
		}

		// Now tmp_evt should contain the evt from which we need to extract our param.
		push_parameter(new_evt, tmp_evt, &params_offset, i, ci->instr[i].param_num, flags);
	}

	// todo!: If we used the enter event we clean it. Use a share pointer since we need it more than
	// once in the for loop.
	new_evt->len = params_offset;
	// If we are still an old event version we need to continue otherwise the conversion is
	// complete.
	PRINT_MESSAGE("Final event:\n");
	PRINT_EVENT(new_evt, PRINT_FULL);
	return scap_is_old_event_version((ppm_event_code)ci->desired_type) ? CONVERSION_CONTINUE
	                                                                   : CONVERSION_COMPLETED;
}

extern "C" scap_evt *retrieve_evt_from_storage(uint64_t tid) {
	return retrieve_evt(tid);
}

extern "C" void clear_evt_storage() {
	clear_storage();
}

extern "C" conversion_result scap_convert_event(scap_evt *new_evt,
                                                scap_evt *evt_to_convert,
                                                char *error) {
	if(evt_to_convert->type >= PPM_EVENT_MAX) {
		snprintf(error, SCAP_LASTERR_SIZE, "Unknown event type '%d'.", evt_to_convert->type);
		return CONVERSION_ERROR;
	}

	if(g_conversion_table.find((ppm_event_code)evt_to_convert->type) != g_conversion_table.end()) {
		return convert_event(new_evt,
		                     evt_to_convert,
		                     &g_conversion_table[(ppm_event_code)evt_to_convert->type],
		                     error);
	}

	// todo!: at the moment we just memcpy the whole event but probably we can improve this.
	memcpy(new_evt, evt_to_convert, evt_to_convert->len);
	return CONVERSION_COMPLETED;
}
