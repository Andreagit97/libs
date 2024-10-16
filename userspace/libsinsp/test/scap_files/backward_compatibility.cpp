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

// Use `sudo ./usr/bin/sysdig -r /home/andrea/Downloads/old_scaps/2013_apache.scap -S -q` to check
// the number of events
TEST_F(savefile_test, no_open_e) {
	open_filepath("/home/andrea/Downloads/old_scaps/2013_apache.scap");
	// There are `8762` PPME_SYSCALL_OPEN_E events in the scap file. No we should have them.
	assert_no_event_type(PPME_SYSCALL_OPEN_E);
}

TEST_F(savefile_test, open_same_number_of_events) {
	open_filepath("/home/andrea/Downloads/old_scaps/2013_apache.scap");
	// There are `8763` PPME_SYSCALL_OPEN_E events in the scap file. We should have the same number
	assert_event_type_count(PPME_SYSCALL_OPEN, 8763);
}

// todo!: do the same test on an older scap-file
TEST_F(savefile_test, check_final_converted_event) {
	// open_filename("kexec_x86.scap");

	// The event number 161211 was:
	// PPME_SYSCALL_OPEN_X, tid: 107370, pid: 107370, fd: 3, flags: 0, mode: 0, pathname:
	// Now it should be
	// PPME_SYSCALL_OPEN, tid: 107370, pid: 107370, fd: 3, flags: 0, mode: 0, pathname:
	// assert_event_num_equal(161211, 161211, 107370, PPME_SYSCALL_OPEN, 6, NULL);
}
