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
#include <functional>
#include <cstring>
#include <cstdio>
#include <unordered_map>

/* ============================= Converters ============================= */

/////////////////////////////
// GENERIC
/////////////////////////////

conversion_result conversion_skip(scap_evt *new_evt, scap_evt *evt_to_convert, char *error) {
	return CONVERSION_SKIP;
}

conversion_result conversion_completed(scap_evt *new_evt, scap_evt *evt_to_convert, char *error) {
	// todo!: at the moment we just memcpy the whole event but probably we can improve this.
	memcpy(new_evt, evt_to_convert, evt_to_convert->len);
	return CONVERSION_COMPLETED;
}

/////////////////////////////
// OPEN
/////////////////////////////

conversion_result convert_PPME_SYSCALL_OPEN_X(scap_evt *new_evt,
                                              scap_evt *evt_to_convert,
                                              char *error) {
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
		fill_missing_parameters_with_default(new_evt, &offset);
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
}

/////////////////////////////
// BRK
/////////////////////////////

conversion_result convert_PPME_SYSCALL_BRK_1_X(scap_evt *new_evt,
                                               scap_evt *evt_to_convert,
                                               char *error) {
	if(validate_nparams(evt_to_convert, error, 1, 1) == CONVERSION_ERROR) {
		return CONVERSION_ERROR;
	}

	// - Num params: 1
	// - p(0): res
	// We want to convert it to PPME_SYSCALL_BRK_4_X with 4 parameters.

	uint16_t offset = copy_first_n_lengths_and_header(new_evt, evt_to_convert, 1);
	// we want to change the event type here because otherwise we will access the wrong
	// entry in the event table
	change_event_type(new_evt, PPME_SYSCALL_BRK_4_X);
	fill_missing_lengths(new_evt, &offset);
	copy_params(new_evt, evt_to_convert, 1, &offset);
	fill_missing_parameters_with_default(new_evt, &offset);
	return CONVERSION_CONTINUE;
}

conversion_result convert_PPME_SYSCALL_BRK_4_E(scap_evt *new_evt,
                                               scap_evt *evt_to_convert,
                                               char *error) {
	if(validate_nparams(evt_to_convert, error, 1, 1) == CONVERSION_ERROR) {
		return CONVERSION_ERROR;
	}

	store_evt(evt_to_convert->tid, evt_to_convert);
	return CONVERSION_SKIP;
}

conversion_result convert_PPME_SYSCALL_BRK_4_X(scap_evt *new_evt,
                                               scap_evt *evt_to_convert,
                                               char *error) {
	if(validate_nparams(evt_to_convert, error, 1, 4) == CONVERSION_ERROR) {
		return CONVERSION_ERROR;
	}

	// - Num params: 4
	// - p(0): res, p(1): vm_size, p(2): vm_rss, p(3): vm_swap
	// We want to convert it to PPME_SYSCALL_BRK with 5 parameters.

	uint16_t offset = copy_first_n_lengths_and_header(new_evt, evt_to_convert, 4);
	change_event_type(new_evt, PPME_SYSCALL_BRK);
	fill_missing_lengths(new_evt, &offset);
	copy_params(new_evt, evt_to_convert, 4, &offset);

	// If we are able to retrieve the enter event we should copy the value from the enter event
	// otherwise we use the default for that type.
	auto enter_evt = retrieve_evt(evt_to_convert->tid);
	if(enter_evt) {
		auto addr_len = get_param_len(enter_evt, 0);
		char *addr = get_param_ptr(enter_evt, 0);
		fill_missing_parameters(new_evt, &offset, 2, addr_len, addr);
	} else {
		fill_missing_parameters_with_default(new_evt, &offset);
	}
	return CONVERSION_COMPLETED;
}

/////////////////////////////
// READ
/////////////////////////////

conversion_result convert_PPME_SYSCALL_READ_E(scap_evt *new_evt,
                                              scap_evt *evt_to_convert,
                                              char *error) {
	if(validate_nparams(evt_to_convert, error, 1, 2) == CONVERSION_ERROR) {
		return CONVERSION_ERROR;
	}

	store_evt(evt_to_convert->tid, evt_to_convert);
	return CONVERSION_SKIP;
}

conversion_result convert_PPME_SYSCALL_READ_X(scap_evt *new_evt,
                                              scap_evt *evt_to_convert,
                                              char *error) {
	if(validate_nparams(evt_to_convert, error, 1, 2) == CONVERSION_ERROR) {
		return CONVERSION_ERROR;
	}

	// - Num params: 2
	// - p(0): res, p(1): data
	// We want to convert it to PPME_SYSCALL_READ with 4 parameters.

	// todo!: we will improve it at the next iteration.
	uint16_t offset = copy_header(new_evt, evt_to_convert);
	change_event_type(new_evt, PPME_SYSCALL_READ);
	uint16_t len_offset = offset;
	uint16_t param_offset = offset + 4 * sizeof(uint16_t);

	// param 1
	uint16_t len = 4;
	memcpy((char *)new_evt + len_offset, &len, (sizeof(uint16_t)));
	len_offset += sizeof(uint16_t);

	auto prt = get_param_ptr(evt_to_convert, 0);
	memcpy((char *)new_evt + param_offset, prt, len);
	param_offset += len;

	// param 2
	len = get_param_len(evt_to_convert, 1);
	memcpy((char *)new_evt + len_offset, &len, (sizeof(uint16_t)));
	len_offset += sizeof(uint16_t);

	prt = get_param_ptr(evt_to_convert, 1);
	memcpy((char *)new_evt + param_offset, prt, len);
	param_offset += len;

	auto enter_evt = retrieve_evt(evt_to_convert->tid);
	if(enter_evt) {
		// param 3
		len = 4;
		memcpy((char *)new_evt + len_offset, &len, (sizeof(uint16_t)));
		len_offset += sizeof(uint16_t);

		prt = get_param_ptr(enter_evt, 0);
		memcpy((char *)new_evt + param_offset, prt, len);
		param_offset += len;

		// param 4
		len = get_param_len(enter_evt, 1);
		memcpy((char *)new_evt + len_offset, &len, (sizeof(uint16_t)));
		len_offset += sizeof(uint16_t);

		prt = get_param_ptr(enter_evt, 1);
		memcpy((char *)new_evt + param_offset, prt, len);
		param_offset += len;
		new_evt->len = param_offset;
		new_evt->nparams = 4;
	} else {
		len = 4;
		memcpy((char *)new_evt + len_offset, &len, (sizeof(uint16_t)));
		len_offset += sizeof(uint16_t);
		memcpy((char *)new_evt + len_offset, &len, (sizeof(uint16_t)));
		len_offset += sizeof(uint16_t);

		fill_missing_parameters_with_default(new_evt, &param_offset);
	}
	return CONVERSION_COMPLETED;
}

/* ============================= Converters ============================= */

using conv_func_t = conversion_result (*)(scap_evt *new_evt, scap_evt *evt_to_convert, char *error);

static std::unordered_map<ppm_event_code, conv_func_t> g_conversion_table = {
        {PPME_SYSCALL_OPEN_E, conversion_skip},
        {PPME_SYSCALL_OPEN_X, convert_PPME_SYSCALL_OPEN_X},
        {PPME_SYSCALL_BRK_1_E, conversion_skip},
        {PPME_SYSCALL_BRK_1_X, convert_PPME_SYSCALL_BRK_1_X},
        {PPME_SYSCALL_BRK_4_E, convert_PPME_SYSCALL_BRK_4_E},
        {PPME_SYSCALL_BRK_4_X, convert_PPME_SYSCALL_BRK_4_X},
        {PPME_SYSCALL_READ_E, convert_PPME_SYSCALL_READ_E},
        {PPME_SYSCALL_READ_X, convert_PPME_SYSCALL_READ_X},
};

conversion_result call_conversion(scap_evt *new_evt, scap_evt *evt_to_convert, char *error) {
	if(evt_to_convert->type >= PPM_EVENT_MAX) {
		snprintf(error, SCAP_LASTERR_SIZE, "Unknown event type '%d'.", evt_to_convert->type);
		return CONVERSION_ERROR;
	}

	if(g_conversion_table.find((ppm_event_code)evt_to_convert->type) != g_conversion_table.end()) {
		return g_conversion_table[(ppm_event_code)evt_to_convert->type](new_evt,
		                                                                evt_to_convert,
		                                                                error);
	}

	return conversion_completed(new_evt, evt_to_convert, error);
}
