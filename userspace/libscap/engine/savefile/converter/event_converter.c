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

#include <stdio.h>
#include <stdarg.h>
#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/engine/savefile/converter/event_converter.h>

// Debugging Macros
#define CONVERSION_DEBUGGING 0

#if CONVERSION_DEBUGGING
#define PRINT_MESSAGE(...) printf("[DEBUG]: " __VA_ARGS__)
#define PRINT_EVENT(ev, i)   \
	printf("\n");            \
	scap_print_event(ev, i); \
	printf("\n");
#else
#define PRINT_MESSAGE(...)
#define PRINT_EVENT(ev, i)
#endif

static void change_event_type(scap_evt *evt, uint16_t event_type) {
	evt->type = event_type;
}

static void copy_old_event(scap_evt *new_evt, scap_evt *evt_to_convert) {
	memcpy(new_evt, evt_to_convert, evt_to_convert->len);
	PRINT_MESSAGE("New copied event:\n");
	PRINT_EVENT(new_evt, PRINT_FULL);
}

static void change_param_len_from_s64_to_s32(scap_evt *e, uint8_t param_idx) {
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
static const char *get_event_name(ppm_event_code event_type) {
	const struct ppm_event_info *event_info = &g_event_info[event_type];
	return event_info->name;
}

static char get_direction_char(ppm_event_code event_type) {
	if(event_type > PPME_SYSCALL_OPEN) {
		return ' ';
	}

	if(PPME_IS_ENTER(event_type)) {
		return 'E';
	} else {
		return 'X';
	}
}

static conversion_result validate_nparams(scap_evt *evt, char *error, int num_valid_params, ...) {
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
	         get_event_name(evt->type),
	         get_direction_char(evt->type),
	         evt->type);
	return CONVERSION_ERROR;
}

static conversion_result return_error(scap_evt *evt, char *error) {
	// This should never happen
	snprintf(error, SCAP_LASTERR_SIZE, "Reached unkown state for event '%d'.", evt->type);
	return CONVERSION_ERROR;
}

// returns the `offset` of the new event
static uint16_t copy_first_n_lengths_and_header(scap_evt *new_evt,
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

static void fill_missing_lengths(scap_evt *new_evt, uint16_t *offset) {
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

static void copy_params(scap_evt *new_evt,
                        scap_evt *evt_to_convert,
                        uint16_t num_lengths,
                        uint16_t *offset) {
	// This is where the params start inside the event to convert
	uint16_t offset_evt_to_convert = sizeof(scap_evt) + sizeof(uint16_t) * num_lengths;
	uint16_t len_to_copy = evt_to_convert->len - offset_evt_to_convert;

	memcpy((char *)new_evt + *offset, (char *)evt_to_convert + offset_evt_to_convert, len_to_copy);

	PRINT_MESSAGE(
	        "copy the rest of the event to convert (len: %ld) in the new event at offest (%d)\n",
	        len_to_copy,
	        *offset);

	*offset += len_to_copy;
}

static void fill_missing_parameters(scap_evt *new_evt, uint16_t *offset) {
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

conversion_result scap_convert_event(scap_evt *new_evt, scap_evt *evt_to_convert, char *error) {
	switch(evt_to_convert->type) {
		////////////////////////
		// SYSCALL OPEN
		////////////////////////
	case PPME_SYSCALL_OPEN_E:
		// todo!: maybe we could store the event and use it in the exit to handle the old TOCTOU fix
		// but it seems a little bit an overkill for scap-files. At the moment we skip it
		return CONVERSION_SKIP;

	case PPME_SYSCALL_OPEN_X:
		if(validate_nparams(evt_to_convert, error, 2, 4, 6) == CONVERSION_ERROR) {
			return CONVERSION_ERROR;
		}

		if(evt_to_convert->nparams == 4) {
			// - Num params: 4
			// - p(0): fd, p(1): name, p(2): flags, p(3): mode
			// We want to convert it to PPME_SYSCALL_OPEN_X with 6 parameters.

			uint16_t offset = copy_first_n_lengths_and_header(new_evt, evt_to_convert, 4);
			// Now we have header + lengths that are ready.
			fill_missing_lengths(new_evt, &offset);
			// Copy the rest of the parameters we need to keep
			copy_params(new_evt, evt_to_convert, 4, &offset);
			// Now we need to add the missing parameters
			fill_missing_parameters(new_evt, &offset);
			return CONVERSION_CONTINUE;
		}

		if(evt_to_convert->nparams == 6) {
			// - Num params: 6
			// - p(0): fd, p(1): name, p(2): flags, p(3): mode, p(4): dev, p(5): ino
			// We want to convert it to PPME_SYSCALL_OPEN with 6 parameters.

			// Copy the old event in the new one
			copy_old_event(new_evt, evt_to_convert);
			// Change the dimension of a parameter
			change_param_len_from_s64_to_s32(new_evt, 0);
			// Change the event type
			change_event_type(new_evt, PPME_SYSCALL_OPEN);
			return CONVERSION_COMPLETED;
		}
		return return_error(evt_to_convert, error);

	default:
		// For all the event we still need to support
		memcpy(new_evt, evt_to_convert, evt_to_convert->len);
		return CONVERSION_COMPLETED;
		break;
	}

	snprintf(error,
	         SCAP_LASTERR_SIZE,
	         "Reached unkown state for event '%d'.",
	         evt_to_convert->type);
	return CONVERSION_ERROR;
}
