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
	const struct ppm_event_info *event_info = &g_event_info[event_type];
	if(event_info->flags & EF_NEW_VERSION) {
		// this is nor enter nor exit
		return '*';
	}

	if((event_type & 1) == 0) {
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
	uint16_t len = 0;
	char *ptr = 0;
	// we need to write the len into the event.
	uint16_t lens_offset = sizeof(scap_evt) + new_evt_param_num * sizeof(uint16_t);

	// We need to check the types of the old and the new param to be sure we are doing the right
	// thing
	auto new_param_type = g_event_info[new_evt->type].params[new_evt_param_num].type;
	auto tmp_param_type = g_event_info[tmp_evt->type].params[tmp_evt_param_num].type;

	if(new_param_type != tmp_param_type) {
		// Today we know only some cases in which this is possible, if we miss some of them throw an
		// exception.
		if(new_param_type == PT_FD32 && tmp_param_type == PT_FD) {
			// In this case is enough to force a shorter param len. From 8 to 4.
			len = 4;
		} else {
			std::string error = "Try to convert a parameter of type '" +
			                    std::to_string(tmp_param_type) + "' to type '" +
			                    std::to_string(new_param_type) + "'. Uknown conversion.";
			throw std::runtime_error(error);
		}
	} else {
		// If the parameters have the same type (most of the cases) we trust the len of the tmp_evt
		len = get_param_len(tmp_evt, tmp_evt_param_num);
	}

	ptr = get_param_ptr(tmp_evt, tmp_evt_param_num);

	PRINT_MESSAGE(
	        "push param (%d) with len (%d, modified %s) at {params_offest (%d), "
	        "lens_offset (%d)} from param (%d) in %d event\n",
	        new_evt_param_num,
	        len,
	        new_param_type != tmp_param_type ? "yes" : "no",
	        *params_offset,
	        lens_offset,
	        tmp_evt_param_num,
	        tmp_evt->type);

	memcpy((char *)new_evt + *params_offset, ptr, len);
	*params_offset += len;
	memcpy((char *)new_evt + lens_offset, &len, sizeof(uint16_t));
}

static conversion_result convert_event(scap_evt *new_evt,
                                       scap_evt *evt_to_convert,
                                       conversion_info *ci,
                                       char *error) {
	// First we validate the number of parameters if necessary
	if(validate_nparams(evt_to_convert, ci->valid_param_nums, error) == CONVERSION_ERROR) {
		return CONVERSION_ERROR;
	}

	// Skip the convertion if needed
	if(ci->desired_type == C_ACTION_SKIP) {
		return CONVERSION_SKIP;
	}

	// Store the event if needed
	if(ci->desired_type == C_ACTION_STORE) {
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
	// If this is true at the end of the for loop we will free its memory.
	bool used_enter_event = false;

	for(int i = 0; i < PPM_MAX_EVENT_PARAMS; i++) {
		switch(ci->instr[i].flags) {
		case C_INSTR_TERMINATE:
			goto end_conversion;

		case C_INSTR_FROM_DEFAULT:
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

end_conversion:
	if(used_enter_event) {
		// We can free the enter event because we don't need it anymore.
		clear_evt(evt_to_convert->tid);
	}

	new_evt->len = params_offset;

	PRINT_MESSAGE("Final event:\n");
	PRINT_EVENT(new_evt, PRINT_FULL);
	return (g_event_info[ci->desired_type].flags & EF_NEW_VERSION) ? CONVERSION_COMPLETED
	                                                               : CONVERSION_CONTINUE;

	// todo!: This will be the final code to use but today we cannot mark the events as
	// OLD_EVENT_VERSION in the table we can do that only at the end of the work

	// return (g_event_info[ci->desired_type].flags & EF_OLD_VERSION) ? CONVERSION_CONTINUE
	//                                                                : CONVERSION_COMPLETED;
}

extern "C" scap_evt *scap_retrieve_evt_from_converter_storage(uint64_t tid) {
	return retrieve_evt(tid);
}

extern "C" void scap_clear_converter_storage() {
	evt_storage.clear();
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
