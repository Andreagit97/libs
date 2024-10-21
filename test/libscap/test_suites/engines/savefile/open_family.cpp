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

#include "convert_event_test.h"

////////////////////////////
// OPEN FAMILY TESTS
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_OPEN_E_skip) {
	uint64_t ts = 12;
	int64_t tid = 25;

	// The open enter event should be skipped.
	assert_single_conversion_skip(create_safe_scap_event(ts, tid, PPME_SYSCALL_OPEN_E, 0));
}

TEST_F(convert_event_test, PPME_SYSCALL_OPEN_X_3_params) {
	uint64_t ts = 12;
	int64_t tid = 25;
	int64_t fd = 6;
	const char* name = "/etc/passwd";
	uint32_t flags = 0;

	// Today we are not aware of any open event with 3 parameters
	assert_single_conversion_failure(
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_OPEN_X, 3, fd, name, flags));
}

TEST_F(convert_event_test, PPME_SYSCALL_OPEN_X_4_params_to_6) {
	uint64_t ts = 12;
	int64_t tid = 25;
	int64_t fd = 6;
	const char* name = "/etc/passwd";
	uint32_t flags = 0;
	uint32_t mode = 37;
	uint32_t dev = 0;
	uint64_t ino = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_CONTINUE,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_OPEN_X, 4, fd, name, flags, mode),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_OPEN_X,
	                               6,
	                               fd,
	                               name,
	                               flags,
	                               mode,
	                               dev,
	                               ino));
}

TEST_F(convert_event_test, PPME_SYSCALL_OPEN_X_6_params_to_PPME_SYSCALL_OPEN) {
	uint64_t ts = 12;
	int64_t tid = 25;
	int64_t fd = 6;
	const char* name = "/etc/passwd";
	uint32_t flags = 0;
	uint32_t mode = 37;
	uint32_t dev = 0;
	uint64_t ino = 0;

	assert_single_conversion_success(conversion_result::CONVERSION_COMPLETED,
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SYSCALL_OPEN_X,
	                                                        6,
	                                                        fd,
	                                                        name,
	                                                        flags,
	                                                        mode,
	                                                        dev,
	                                                        ino),
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SYSCALL_OPEN,
	                                                        6,
	                                                        (int32_t)fd,
	                                                        name,
	                                                        flags,
	                                                        mode,
	                                                        dev,
	                                                        ino));
}

// This test start with the first event version and convert it to the last one
// Note: the test should be always updated to the latest version.
TEST_F(convert_event_test, PPME_SYSCALL_OPEN_X_full_resolution) {
	uint64_t ts = 12;
	int64_t tid = 25;
	int64_t fd = 6;
	const char* name = "/etc/passwd";
	uint32_t flags = 0;
	uint32_t mode = 37;
	uint32_t dev = 0;
	uint64_t ino = 0;

	assert_full_conversion(
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_OPEN_X, 4, fd, name, flags, mode),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_OPEN,
	                               6,
	                               (int32_t)fd,
	                               name,
	                               flags,
	                               mode,
	                               dev,
	                               ino));
}
