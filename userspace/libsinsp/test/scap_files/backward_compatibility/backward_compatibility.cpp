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

#include <scap_files/scap_file_test.h>

// Use `sudo sysdig -r <scap-file> -S -q` to check the number of events in the scap file.
// When you find a specific event to assert use
// `sudo sysdig -r <> -d "evt.num =<>" -p "ts=%evt.rawtime,tid=%thread.tid,args=%evt.arg.args"`

////////////////////////////
// OPEN
////////////////////////////

TEST_F(scap_file_test, no_open_e) {
	open_filename("scap_2013.scap");
	// There are `8762` PPME_SYSCALL_OPEN_E events in the scap file. We shouldn't have them.
	assert_no_event_type(PPME_SYSCALL_OPEN_E);
}

TEST_F(scap_file_test, open_same_number_of_events) {
	open_filename("scap_2013.scap");
	// There are `8763` PPME_SYSCALL_OPEN_X events in the scap file. We should have the same number
	assert_num_event_type(PPME_SYSCALL_OPEN, 8763);
}

TEST_F(scap_file_test, open_check_final_converted_event) {
	open_filename("scap_2013.scap");

	// Inside the scap-file the event `519652` is the following:
	//
	// type=PPME_SYSCALL_OPEN_X, ts=1380933088302884404, tid=24135, args=fd=5
	// name=/proc/56560/task/56613/statm flags=0(O_NONE) mode=0
	//
	// Let's check if it has been converted to the new event!

	uint64_t ts = 1380933088302884404;
	int64_t tid = 24135;
	int32_t fd = 5;
	const char* name = "/proc/56560/task/56613/statm";
	uint32_t flags = 0;
	uint32_t mode = 0;
	uint32_t dev = 0;
	uint64_t ino = 0;

	assert_event_presence(
	        create_safe_scap_event(ts, tid, PPME_SYSCALL_OPEN, 6, fd, name, flags, mode, dev, ino));
}

////////////////////////////
// BRK
////////////////////////////

TEST_F(scap_file_test, no_brk_1_e) {
	open_filename("scap_2013.scap");
	// There are `69` PPME_SYSCALL_BRK_1_E events in the scap file. We shouldn't have them.
	assert_no_event_type(PPME_SYSCALL_BRK_1_E);
}

TEST_F(scap_file_test, brk_1_x_same_number_of_events) {
	open_filename("scap_2013.scap");
	// There are `69` PPME_SYSCALL_BRK_1_X events in the scap file. We should have the same number.
	assert_num_event_type(PPME_SYSCALL_BRK, 69);
}

TEST_F(scap_file_test, brk_1_x_check_final_converted_event) {
	open_filename("scap_2013.scap");

	// Inside the scap-file the event `414274` is the following:
	//
	// type=PPME_SYSCALL_BRK_1_X, ts=1380933088017303383, tid=44174, args=res=30003200
	//
	// Let's check if it has been converted to the new event!

	uint64_t ts = 1380933088017303383;
	int64_t tid = 44174;

	uint64_t res = 30003200;
	// They should be all 0 since they are all defaulted to 0
	uint32_t vm_size = 0;
	uint32_t vm_rss = 0;
	uint32_t vm_swap = 0;
	uint64_t addr = 0;

	assert_event_presence(create_safe_scap_event(ts,
	                                             tid,
	                                             PPME_SYSCALL_BRK,
	                                             5,
	                                             res,
	                                             vm_size,
	                                             vm_rss,
	                                             vm_swap,
	                                             addr));
}

TEST_F(scap_file_test, no_brk_4_e) {
	open_filename("kexec_x86.scap");
	// There are `284` PPME_SYSCALL_BRK_4_E events in the scap file. We shouldn't have them.
	assert_no_event_type(PPME_SYSCALL_BRK_4_E);
}

TEST_F(scap_file_test, brk_4_x_same_number_of_events) {
	open_filename("kexec_x86.scap");
	// There are `284` PPME_SYSCALL_BRK_4_X events in the scap file. We should have the same number.
	assert_num_event_type(PPME_SYSCALL_BRK, 284);
}
