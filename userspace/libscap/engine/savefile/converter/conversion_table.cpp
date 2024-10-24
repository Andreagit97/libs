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
}

/* ============================= Converters ============================= */

using conv_func_t = conversion_result (*)(scap_evt *new_evt, scap_evt *evt_to_convert, char *error);

static std::unordered_map<ppm_event_code, conv_func_t> g_conversion_table = {
        {PPME_SYSCALL_OPEN_E, conversion_skip},
        {PPME_SYSCALL_OPEN_X, convert_PPME_SYSCALL_OPEN_X},

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
