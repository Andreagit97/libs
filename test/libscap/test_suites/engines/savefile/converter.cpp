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
// OPEN
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

TEST_F(convert_event_test, PPME_SYSCALL_OPEN_X_4_params_to_PPME_SYSCALL_OPEN) {
	uint64_t ts = 12;
	int64_t tid = 25;
	int64_t fd = 6;
	const char* name = "/etc/passwd";
	uint32_t flags = 0;
	uint32_t mode = 37;
	uint32_t dev = 0;
	uint64_t ino = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
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

////////////////////////////
// BRK
////////////////////////////

TEST_F(convert_event_test, PPME_SYSCALL_BRK_1_E_skip) {
	uint64_t ts = 12;
	int64_t tid = 25;
	uint32_t size = 0;

	// The open enter event should be skipped.
	assert_single_conversion_skip(create_safe_scap_event(ts, tid, PPME_SYSCALL_BRK_1_E, 1, size));
}

TEST_F(convert_event_test, PPME_SYSCALL_BRK_1_X_to_PPME_SYSCALL_BRK_4_X) {
	uint64_t ts = 12;
	int64_t tid = 25;

	uint64_t res = 178;

	// These will be always 0 because we are creating them with the default values
	uint32_t vm_size = 0;
	uint32_t vm_rss = 0;
	uint32_t vm_swap = 0;

	assert_single_conversion_success(conversion_result::CONVERSION_CONTINUE,
	                                 create_safe_scap_event(ts, tid, PPME_SYSCALL_BRK_1_X, 1, res),
	                                 create_safe_scap_event(ts,
	                                                        tid,
	                                                        PPME_SYSCALL_BRK_4_X,
	                                                        4,
	                                                        res,
	                                                        vm_size,
	                                                        vm_rss,
	                                                        vm_swap));
}

TEST_F(convert_event_test, store_PPME_SYSCALL_BRK_4_E) {
	uint64_t ts = 12;
	int64_t tid = 25;

	uint64_t addr = 178;

	// we need to keep the memory alive until we check the storage presence
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_BRK_4_E, 1, addr);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(tid, PPME_SYSCALL_BRK_4_E);
}

TEST_F(convert_event_test, PPME_SYSCALL_BRK_4_X_to_PPME_SYSCALL_BRK_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	uint64_t res = 178;
	uint32_t vm_size = 14;
	uint32_t vm_rss = 28;
	uint32_t vm_swap = 39;

	// Address is zero because in this scenario we don't retrieve the enter event
	uint64_t addr = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_BRK_4_X, 4, res, vm_size, vm_rss, vm_swap),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_BRK,
	                               5,
	                               res,
	                               vm_size,
	                               vm_rss,
	                               vm_swap,
	                               addr));
}

TEST_F(convert_event_test, PPME_SYSCALL_BRK_4_X_to_PPME_SYSCALL_BRK_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	uint64_t res = 178;
	uint32_t vm_size = 14;
	uint32_t vm_rss = 28;
	uint32_t vm_swap = 39;

	// We should retrieve the correct `addr` in the final event.
	uint64_t addr = 17;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_BRK_4_E, 1, addr);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(tid, PPME_SYSCALL_BRK_4_E);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_BRK_4_X, 4, res, vm_size, vm_rss, vm_swap),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_BRK,
	                               5,
	                               res,
	                               vm_size,
	                               vm_rss,
	                               vm_swap,
	                               addr));
}

TEST_F(convert_event_test, PPME_SYSCALL_BRK_1_X_to_PPME_SYSCALL_BRK_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	uint64_t res = 178;
	// They should be all 0 since they are all defaulted to 0
	uint32_t vm_size = 0;
	uint32_t vm_rss = 0;
	uint32_t vm_swap = 0;
	uint64_t addr = 0;

	assert_full_conversion(create_safe_scap_event(ts, tid, PPME_SYSCALL_BRK_1_X, 1, res),
	                       create_safe_scap_event(ts,
	                                              tid,
	                                              PPME_SYSCALL_BRK,
	                                              5,
	                                              res,
	                                              vm_size,
	                                              vm_rss,
	                                              vm_swap,
	                                              addr));
}

////////////////////////////
// READ
////////////////////////////

TEST_F(convert_event_test, store_PPME_SYSCALL_READ_E) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t fd = 25;
	uint32_t size = 89;

	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_READ_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	// todo!: compare the acutal event not just the type.
	assert_event_storage_presence(tid, PPME_SYSCALL_READ_E);
}

TEST_F(convert_event_test, PPME_SYSCALL_READ_X_to_PPME_SYSCALL_READ_no_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	uint8_t read_buf[] = {'h', 'e', 'l', 'l', 'o'};

	// Defaulted to 0
	int64_t fd = 0;
	uint32_t size = 0;

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_READ_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_READ,
	                               4,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)},
	                               (int32_t)fd,
	                               size));
}

TEST_F(convert_event_test, PPME_SYSCALL_READ_X_to_PPME_SYSCALL_READ_with_enter) {
	uint64_t ts = 12;
	int64_t tid = 25;

	int64_t res = 89;
	uint8_t read_buf[] = {'h', 'e', 'l', 'l', 'o'};
	int64_t fd = 25;
	uint32_t size = 36;

	// After the first conversion we should have the storage
	auto evt = create_safe_scap_event(ts, tid, PPME_SYSCALL_READ_E, 2, fd, size);
	assert_single_conversion_skip(evt);
	assert_event_storage_presence(tid, PPME_SYSCALL_READ_E);

	assert_single_conversion_success(
	        conversion_result::CONVERSION_COMPLETED,
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_READ_X,
	                               2,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)}),
	        create_safe_scap_event(ts,
	                               tid,
	                               PPME_SYSCALL_READ,
	                               4,
	                               res,
	                               scap_const_sized_buffer{read_buf, sizeof(read_buf)},
	                               (int32_t)fd,
	                               size));
}
