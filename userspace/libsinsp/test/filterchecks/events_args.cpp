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

#include <sinsp_with_test_input.h>

// todo!: can we find a way to automatically generate these tests?
TEST_F(sinsp_with_test_input, evt_arg_open_success) {
	add_default_init_thread();
	open_inspector();

	int32_t fd = 5;
	const char* name = "/proc/56560/task/56613/statm";
	uint32_t flags = PPM_O_APPEND | PPM_O_CREAT | PPM_O_RDWR;
	uint32_t mode = PPM_S_IRUSR | PPM_S_IWUSR | PPM_S_IRGRP | PPM_S_IROTH;
	uint32_t dev = 324;
	uint64_t ino = 534;

	sinsp_evt* evt = generate_open_event(sinsp_test_input::open_params{.fd = fd,
	                                                                   .path = name,
	                                                                   .flags = flags,
	                                                                   .mode = mode,
	                                                                   .dev = dev,
	                                                                   .ino = ino});

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), "<f>/proc/56560/task/56613/statm");
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.fd32_rename"), std::to_string(fd));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), name);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.name"), name);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[2]"), "O_APPEND|O_CREAT|O_RDWR");
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.flags"), std::to_string(flags));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[3]"),
	          "0644");  // octal notation of 420 formatted as string.
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.mode"),
	          "644");  // todo!: not sure we want this and not the decimal value like with dev

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[4]"), "144");  // hexadecimal notation
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.dev"), std::to_string(dev));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[5]"), std::to_string(ino));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.ino"), std::to_string(ino));
}

TEST_F(sinsp_with_test_input, evt_arg_open_failure) {
	add_default_init_thread();
	open_inspector();

	int32_t fd = -3;
	sinsp_evt* evt = generate_open_event(sinsp_test_input::open_params{.fd = fd});
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), "ESRCH");
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.fd32_rename"), std::to_string(fd));
}

TEST_F(sinsp_with_test_input, evt_arg_brk) {
	add_default_init_thread();
	open_inspector();

	uint64_t res = 2808032;
	uint32_t vm_size = 294;
	uint32_t vm_rss = 295;
	uint32_t vm_swap = 296;
	uint64_t addr = 83983092;

	// todo!: do we want to create a helper for this like for open?
	auto evt = add_event_advance_ts(increasing_ts(),
	                                INIT_TID,
	                                PPME_SYSCALL_BRK,
	                                5,
	                                res,
	                                vm_size,
	                                vm_rss,
	                                vm_swap,
	                                addr);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), "2AD8E0");  // hexadecimal notation
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.res"), std::to_string(res));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), std::to_string(vm_size));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.vm_size"), std::to_string(vm_size));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[2]"), std::to_string(vm_rss));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.vm_rss"), std::to_string(vm_rss));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[3]"), std::to_string(vm_swap));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.vm_swap"), std::to_string(vm_swap));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[4]"), "5017AF4");  // hexadecimal notation
	// todo!: this is broken because due to the longest prefix match we think that `addr` is a
	// SOCKADDR parameter ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.addr"),
	// std::to_string(addr));
}
