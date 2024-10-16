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

#include "savefile_test.h"

////////////////////////////
// OPEN FAMILY TESTS
////////////////////////////

TEST_F(savefile_test, open_invalid_num_params) {
	// auto evt_to_convert = create_event(0, 0, PPM_EVENT_NONE, 0, nullptr);
	// auto evt_new = create_event(0, 0, PPM_EVENT_NONE, 0, nullptr);
	// m_new_event = NULL;
	// char error[SCAP_LASTERR_SIZE] = {'\0'};
	// scap_convert_event((scap_evt*)m_new_event, evt_to_convert, error);
}

TEST_F(savefile_test, open_4_params_to_6) {
	uint64_t ts = 12;
	int64_t tid = 25;
	int64_t fd = 6;
	const char* name = "/etc/passwd";
	uint32_t flags = 0;
	uint32_t mode = 37;
	uint32_t dev = 0;
	uint64_t ino = 0;

	assert_conversion(
	        conversion_result::CONVERSION_CONTINUE,
	        create_event(ts, tid, PPME_SYSCALL_OPEN_X, 4, fd, name, flags, mode),
	        create_event(ts, tid, PPME_SYSCALL_OPEN_X, 6, fd, name, flags, mode, dev, ino));
}

TEST_F(savefile_test, open_6_params) {}

TEST_F(savefile_test, open_new_event) {}
