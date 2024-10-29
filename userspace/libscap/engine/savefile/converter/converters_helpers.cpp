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

#include <driver/ppm_events_public.h>
#include <converter/conversion_types.h>
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

conversion_result validate_nparams(scap_evt *evt, char *error, int num_valid_params, ...) {
	va_list args;
	va_start(args, num_valid_params);

	for(int i = 0; i < num_valid_params; ++i) {
		int valid_param = va_arg(args, int);
		if(evt->nparams == valid_param) {
			va_end(args);
			return CONVERSION_CONTINUE;
		}
	}

	va_end(args);
	snprintf(error,
	         SCAP_LASTERR_SIZE,
	         "Unknown number of parameters '%d' for event '%s_%c(num: %d)'.",
	         evt->nparams,
	         get_event_name((ppm_event_code)evt->type),
	         get_direction_char((ppm_event_code)evt->type),
	         evt->type);
	return CONVERSION_ERROR;
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

	PRINT_MESSAGE("New header:\n");
	PRINT_EVENT(new_evt, PRINT_HEADER);
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
