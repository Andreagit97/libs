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

conversion_result scap_convert_event(scap_evt *new_evt, scap_evt *evt_to_convert, char *error) {
	switch(evt_to_convert->type) {
	// todo!: maybe we could store the event and use it in the exit to handle the old TOCTOU fix but
	// it seems a little bit an overkill for scap-files. At the moment we skip it
	case PPME_SYSCALL_OPEN_E:
		return CONVERSION_SKIP;

	case PPME_SYSCALL_OPEN_X:

		// Known event versions
		// todo!: this could be come an helper function or a macro, since we need it for all events.
		if((evt_to_convert->nparams != 4) && (evt_to_convert->nparams != 6)) {
			snprintf(error,
			         SCAP_LASTERR_SIZE,
			         "Unknown number of parametes '%d' for event '%s_%c(num: %d)'.",
			         evt_to_convert->nparams,
			         get_event_name(evt_to_convert->type),
			         get_direction_char(evt_to_convert->type),
			         evt_to_convert->type);
			return CONVERSION_ERROR;
		}

		if(evt_to_convert->nparams == 4) {
			// - Num params: 4
			// - p(0): fd, p(1): name, p(2): flags, p(3): mode
			// We want to convert it to the new event with 6 parameters.

			// todo!: we need to create some helpers methods

			PRINT_MESSAGE("Event to convert:\n");
			PRINT_EVENT(evt_to_convert, PRINT_FULL);

			// We keep the header and the first 4 lengths: fd, name, flags, mode.
			int offset = sizeof(scap_evt) + sizeof(uint16_t) * 4;
			memcpy(new_evt, evt_to_convert, offset);

			PRINT_MESSAGE("Copy header and first 4 length. Tmp new event:\n");
			PRINT_EVENT(new_evt, PRINT_HEADER_LENGTHS);

			// But we need to add 2 new parameters
			const struct ppm_event_info *event_info = &(g_event_info[evt_to_convert->type]);

			// Add the last 2 parameters len
			uint16_t len = scap_get_size_bytes_from_type(event_info->params[4].type);
			PRINT_MESSAGE("push len (%d) for param (%d, type: %d) at offest (%d)\n",
			              len,
			              4,
			              event_info->params[4].type,
			              offset);
			memcpy((char *)new_evt + offset, &len, sizeof(uint16_t));
			PRINT_MESSAGE("pushed: %d\n", *((uint16_t *)&new_evt[offset]));
			offset += sizeof(uint16_t);

			len = scap_get_size_bytes_from_type(event_info->params[5].type);
			PRINT_MESSAGE("push len (%d) for param (%d, type: %d) at offest (%d)\n",
			              len,
			              5,
			              event_info->params[5].type,
			              offset);
			memcpy((char *)new_evt + offset, &len, sizeof(uint16_t));
			offset += sizeof(uint16_t);

			// Adjust the number of parameters
			new_evt->nparams = 6;

			PRINT_MESSAGE("Added the last 2 parameters len. Print header + lengths:\n");
			PRINT_EVENT(new_evt, PRINT_HEADER_LENGTHS);

			// Copy the rest of the event to convert.
			memcpy((char *)new_evt + offset,
			       (char *)evt_to_convert + sizeof(scap_evt) + sizeof(uint16_t) * 4,
			       evt_to_convert->len - (sizeof(scap_evt) + sizeof(uint16_t) * 4));
			PRINT_MESSAGE("copy the rest of the event (len: %ld) at offest (%d)\n",
			              evt_to_convert->len - (sizeof(scap_evt) + sizeof(uint16_t) * 4),
			              offset);
			offset += (evt_to_convert->len - (sizeof(scap_evt) + sizeof(uint16_t) * 4));

			// Add the last 2 parameters
			char *value = scap_get_default_value_from_type(event_info->params[4].type);
			PRINT_MESSAGE("push param (%d, type: %d) at offest (%d)\n",
			              4,
			              event_info->params[4].type,
			              offset);
			memcpy((char *)new_evt + offset,
			       value,
			       scap_get_size_bytes_from_type(event_info->params[4].type));
			offset += scap_get_size_bytes_from_type(event_info->params[4].type);

			value = scap_get_default_value_from_type(event_info->params[5].type);
			PRINT_MESSAGE("push param (%d, type: %d) at offest (%d)\n",
			              5,
			              event_info->params[5].type,
			              offset);
			memcpy((char *)new_evt + offset,
			       value,
			       scap_get_size_bytes_from_type(event_info->params[5].type));
			offset += scap_get_size_bytes_from_type(event_info->params[5].type);

			// We need to adapt the new event len
			new_evt->len = offset;

			PRINT_MESSAGE("Final event:\n");
			PRINT_EVENT(new_evt, PRINT_FULL);

			return CONVERSION_CONTINUE;
		}

		if(evt_to_convert->nparams == 6) {
			// - Num params: 6
			// - p(0): fd, p(1): name, p(2): flags, p(3): mode, p(4): dev, p(5): ino

			// Copy the old event in the new one
			copy_old_event(new_evt, evt_to_convert);

			// Change the dimension of a parameter
			change_param_len_from_s64_to_s32(new_evt, 0);

			// Change the event type
			change_event_type(new_evt, PPME_SYSCALL_OPEN);
			return CONVERSION_COMPLETED;
		}
		// This should never happen
		snprintf(error, SCAP_LASTERR_SIZE, "Reached unkown state for event '%d'.", new_evt->type);
		return CONVERSION_ERROR;

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
