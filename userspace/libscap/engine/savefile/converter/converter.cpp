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
#include <converter/types.h>
#include <converter/results.h>
#include <converter/table.h>
#include <converter/debug_macro.h>
#include <stdarg.h>
#include <cstdio>
#include <cassert>
#include <unordered_map>
#include <string>
#include <stdexcept>
#include <memory>

typedef std::shared_ptr<scap_evt> safe_scap_evt_t;

static inline safe_scap_evt_t safe_scap_evt(scap_evt *evt) {
	return safe_scap_evt_t{evt, free};
}

// use a shared pointer to store the events
static std::unordered_map<uint64_t, safe_scap_evt_t> evt_storage = {};

extern const struct ppm_event_info g_event_info[];

static const char *get_event_name(ppm_event_code event_type) {
	const struct ppm_event_info *event_info = &g_event_info[event_type];
	return event_info->name;
}

static char get_direction_char(ppm_event_code event_type) {
	if(PPME_IS_ENTER(event_type)) {
		return 'E';
	} else {
		return 'X';
	}
}

static void clear_evt(uint64_t tid) {
	if(evt_storage.find(tid) != evt_storage.end()) {
		evt_storage[tid].reset();
	}
}

static void store_evt(uint64_t tid, scap_evt *evt) {
	// if there was a previous event for this tid, we can overwrite the pointer because it means we
	// don't need it anymore. We need to keep the enter event until we retrieve it in the
	// corresponding exit event, but if the same thread is doing another enter event it means the
	// previous syscall is already completed.

	clear_evt(tid);

	scap_evt *tmp_evt = (scap_evt *)malloc(evt->len);
	if(!tmp_evt) {
		throw std::runtime_error("Cannot allocate memory for the enter event.");
	}
	memcpy(tmp_evt, evt, evt->len);
	evt_storage[tid] = safe_scap_evt(tmp_evt);
}

static scap_evt *retrieve_evt(uint64_t tid) {
	if(evt_storage.find(tid) != evt_storage.end()) {
		return evt_storage[tid].get();
	}
	return nullptr;
}

static uint16_t get_param_len(scap_evt *evt, uint8_t num_param) {
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

static char *get_param_ptr(scap_evt *evt, uint8_t num_param) {
	if(evt->nparams <= num_param) {
		std::string error = "Try to access param num '" + std::to_string(num_param) +
		                    "' for event " + get_event_name((ppm_event_code)evt->type) + "_" +
		                    get_direction_char((ppm_event_code)evt->type) +
		                    " (num parameters: " + std::to_string(evt->type) + ").";
		throw std::runtime_error(error);
	}

	char *ptr = (char *)evt + sizeof(scap_evt) + sizeof(uint16_t) * evt->nparams;
	uint16_t ptr_off = 0;
	for(auto i = 0; i < num_param; i++) {
		uint16_t len = 0;
		memcpy(&len, (char *)evt + sizeof(scap_evt) + sizeof(uint16_t) * i, sizeof(uint16_t));
		ptr_off += len;
	}

	return ptr + ptr_off;
}

static conversion_result validate_nparams(scap_evt *evt,
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
static void push_default_parameter(scap_evt *evt, uint16_t *params_offset, uint8_t param_num) {
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

// This writes len + the param
static void push_parameter(scap_evt *new_evt,
                           scap_evt *tmp_evt,
                           uint16_t *params_offset,
                           uint8_t new_evt_param_num,
                           uint8_t tmp_evt_param_num) {
	// we need to write the len into the event.
	uint16_t lens_offset = sizeof(scap_evt) + new_evt_param_num * sizeof(uint16_t);
	uint16_t len = get_param_len(tmp_evt, tmp_evt_param_num);
	char *ptr = get_param_ptr(tmp_evt, tmp_evt_param_num);

	PRINT_MESSAGE(
	        "push param (%d, type: %d) with len (%d) at {params_offest: %d, "
	        "lens_offset: %d} from event type '%d', param '%d'\n",
	        new_evt_param_num,
	        g_event_info[tmp_evt->type].params[tmp_evt_param_num].type,
	        len,
	        *params_offset,
	        lens_offset,
	        tmp_evt->type,
	        tmp_evt_param_num);

	memcpy((char *)new_evt + *params_offset, ptr, len);
	*params_offset += len;
	memcpy((char *)new_evt + lens_offset, &len, sizeof(uint16_t));
}

// static uint16_t copy_old_event_content(scap_evt *new_evt, scap_evt *old_evt) {
// 	// Copy the header
// 	memcpy(new_evt, old_evt, sizeof(scap_evt));

// 	// Copy the legths array of the old event.
// 	memcpy((char *)new_evt + sizeof(scap_evt),
// 	       (char *)old_evt + sizeof(scap_evt),
// 	       old_evt->nparams * sizeof(uint16_t));

// 	// NO: THIS IS WRONG! It doesn't work when we change type.
// 	new_evt->nparams = g_event_info[old_evt->type].nparams;

// 	// Copy the parameters from the old event
// 	uint16_t new_event_params_offset = sizeof(scap_evt) + new_evt->nparams * sizeof(uint16_t);
// 	uint16_t old_event_params_offset = sizeof(scap_evt) + old_evt->nparams * sizeof(uint16_t);
// 	uint16_t size_to_copy = old_evt->len - old_event_params_offset;
// 	memcpy((char *)new_evt + new_event_params_offset,
// 	       (char *)old_evt + old_event_params_offset,
// 	       size_to_copy);

// 	return new_event_params_offset + size_to_copy;
// }

static conversion_result convert_event(scap_evt *new_evt,
                                       scap_evt *evt_to_convert,
                                       conversion_info *ci,
                                       char *error) {
	/////////////////////////////
	// Validate the number of parameters (if necessary)
	/////////////////////////////

	if(validate_nparams(evt_to_convert, ci->valid_param_nums, error) == CONVERSION_ERROR) {
		return CONVERSION_ERROR;
	}

	/////////////////////////////
	// Dispatch the action
	/////////////////////////////

	switch(ci->action) {
	case C_ACTION_SKIP:
		return CONVERSION_SKIP;

	case C_ACTION_STORE:
		store_evt(evt_to_convert->tid, evt_to_convert);
		return CONVERSION_SKIP;

	case C_ACTION_FILL:
	case C_ACTION_CHANGE_TYPE:
		break;

	default:
		snprintf(error, SCAP_LASTERR_SIZE, "Unhandled conversion action '%d'.", ci->action);
		return CONVERSION_ERROR;
	}

	/////////////////////////////
	// Fill the event to its most recent version
	/////////////////////////////

	memcpy(new_evt, evt_to_convert, sizeof(scap_evt));
	// The new number of params we want is the number of conversion instructions.
	new_evt->nparams = ci->instr.size();
	PRINT_MESSAGE("New event header (the len is still the old one):\n");
	PRINT_EVENT(new_evt, PRINT_HEADER);

	// Change the type here if needed because we will need this information when we push default
	// params
	if(ci->action == C_ACTION_CHANGE_TYPE) {
		new_evt->type = ci->desired_type;
	}

	uint16_t params_offset = sizeof(scap_evt) + new_evt->nparams * sizeof(uint16_t);

	scap_evt *tmp_evt = NULL;
	// If this is true at the end of the for loop we will free its memory.
	bool used_enter_event = false;

	for(int i = 0; i < new_evt->nparams; i++) {
		// The old event always wins.
		if(i < evt_to_convert->nparams) {
			ci->instr[i].flags = C_INSTR_FROM_OLD;
			ci->instr[i].param_num = i;
		}

		switch(ci->instr[i].flags) {
		case C_INSTR_FROM_DEFAULT:
			if(ci->action != C_ACTION_CHANGE_TYPE) {
				snprintf(error,
				         SCAP_LASTERR_SIZE,
				         "Cannot use the default value when not changing the type.");
				return CONVERSION_ERROR;
			}

			if(new_evt->type != ci->desired_type) {
				snprintf(error,
				         SCAP_LASTERR_SIZE,
				         "The new type is not updated with the desired one. We won't find the "
				         "default value.");
				return CONVERSION_ERROR;
			}

			tmp_evt = NULL;
			break;

		case C_INSTR_FROM_ENTER:
			tmp_evt = retrieve_evt(evt_to_convert->tid);
			if(!tmp_evt) {
				// If there is no the enter event because we dropped it in the capture or we come
				// here from another conversion (see the BRK_1 example) we get the default value.
				break;
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
			used_enter_event = true;
			break;

		case C_INSTR_FROM_OLD:
			tmp_evt = evt_to_convert;
			if(tmp_evt->nparams <= i) {
				// If this is an old version we don't have the available parameters so we get the
				// default value (see OPEN_X example).
				tmp_evt = NULL;
			}
			break;

		default:
			snprintf(error,
			         SCAP_LASTERR_SIZE,
			         "Unknown instruction (flags: %d, param_num: %d).",
			         ci->instr[i].flags,
			         ci->instr[i].param_num);
			return CONVERSION_ERROR;
		}

		if(!tmp_evt) {
			push_default_parameter(new_evt, &params_offset, i);
		} else {
			push_parameter(new_evt, tmp_evt, &params_offset, i, ci->instr[i].param_num);
		}
	}

	if(used_enter_event) {
		// We can free the enter event because we don't need it anymore.
		clear_evt(evt_to_convert->tid);
	}

	new_evt->len = params_offset;

	PRINT_MESSAGE("Final event:\n");
	PRINT_EVENT(new_evt, PRINT_FULL);
	return ci->action == C_ACTION_CHANGE_TYPE ? CONVERSION_CONTINUE : CONVERSION_COMPLETED;
}

extern "C" scap_evt *scap_retrieve_evt_from_converter_storage(uint64_t tid) {
	return retrieve_evt(tid);
}

extern "C" void scap_clear_converter_storage() {
	evt_storage.clear();
}

extern "C" bool is_conversion_needed(scap_evt *evt_to_convert) {
	assert(evt_to_convert->type < PPM_EVENT_MAX);

	// If we don't even have the entry for sure we don't need a conversion.
	if(g_conversion_table.find((ppm_event_code)evt_to_convert->type) == g_conversion_table.end()) {
		return false;
	}

	// Even if we have the entry we can skip the conversion in the following cases:
	// - The action is `C_ACTION_FILL` && we already have the right number of parameters we can skip
	conversion_info *ci = &g_conversion_table[(ppm_event_code)evt_to_convert->type];
	if(ci->action == C_ACTION_FILL && evt_to_convert->nparams == ci->instr.size()) {
		return false;
	}

	// We need the conversion
	return true;
}

extern "C" conversion_result scap_convert_event(scap_evt *new_evt,
                                                scap_evt *evt_to_convert,
                                                char *error) {
	// This should be checked by the caller but just double check here
	if(!is_conversion_needed(evt_to_convert)) {
		snprintf(error,
		         SCAP_LASTERR_SIZE,
		         "Conversion not need for event type '%d' nparams '%d'. Please double check",
		         evt_to_convert->type,
		         evt_to_convert->nparams);
		return CONVERSION_ERROR;
	}

	// If we reached this point we have for sure an entry in the conversion table.
	return convert_event(new_evt,
	                     evt_to_convert,
	                     &g_conversion_table[(ppm_event_code)evt_to_convert->type],
	                     error);
}
