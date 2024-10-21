// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <test/helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, FD_FILTER_filename) {
	add_default_init_thread();
	open_inspector();

	auto evt = generate_open_event();
	ASSERT_TRUE(field_has_value(evt, "fd.filename"));
	ASSERT_EQ(get_field_as_string(evt, "fd.filename"),
	          sinsp_test_input::open_params::default_filename);
}

TEST_F(sinsp_with_test_input, FD_FILTER_is_lower_layer) {
	add_default_init_thread();
	open_inspector();

	uint32_t flags = PPM_O_RDONLY | PPM_FD_LOWER_LAYER;
	auto evt = generate_open_event(sinsp_test_input::open_params{.flags = flags});
	ASSERT_EQ(get_field_as_string(evt, "fd.is_lower_layer"), "true");
	ASSERT_EQ(get_field_as_string(evt, "fd.is_upper_layer"), "false");
	ASSERT_TRUE(evt->get_fd_info());
	ASSERT_EQ(evt->get_fd_info()->is_overlay_lower(), true);
	ASSERT_EQ(evt->get_fd_info()->is_overlay_upper(), false);
	ASSERT_EQ(evt->get_fd_info()->m_openflags, flags);
}

TEST_F(sinsp_with_test_input, FD_FILTER_is_upper_layer) {
	add_default_init_thread();
	open_inspector();

	uint32_t flags = PPM_O_WRONLY | PPM_FD_UPPER_LAYER;
	auto evt = generate_open_event(sinsp_test_input::open_params{.flags = flags});
	ASSERT_EQ(get_field_as_string(evt, "fd.is_lower_layer"), "false");
	ASSERT_EQ(get_field_as_string(evt, "fd.is_upper_layer"), "true");
	ASSERT_TRUE(evt->get_fd_info());
	ASSERT_EQ(evt->get_fd_info()->is_overlay_lower(), false);
	ASSERT_EQ(evt->get_fd_info()->is_overlay_upper(), true);
	ASSERT_EQ(evt->get_fd_info()->m_openflags, flags);
}

TEST_F(sinsp_with_test_input, FD_FILTER_fd_types) {
	add_default_init_thread();
	open_inspector();

	sinsp_evt* evt = generate_open_event(sinsp_test_input::open_params{.fd = 1});
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN);
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "1");
	ASSERT_EQ(get_field_as_string(evt, "fd.types[1]"), "(file)");
	ASSERT_EQ(get_field_as_string(evt, "fd.types"), "(file)");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_E, 1, (int64_t)0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_X, 1, (int64_t)2);
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_BPF_2_X);
	ASSERT_EQ(get_field_as_string(evt, "fd.num"), "2");
	ASSERT_EQ(get_field_as_string(evt, "fd.type"), "bpf");
	ASSERT_EQ(get_field_as_string(evt, "fd.types[1]"), "(file)");
	ASSERT_EQ(get_field_as_string(evt, "fd.types[2]"), "(bpf)");
	ASSERT_EQ(get_field_as_string(evt, "fd.types"), "(bpf,file)");

	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_E, 1, (int64_t)0);
	evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_BPF_2_X, 1, (int64_t)3);

	ASSERT_EQ(get_field_as_string(evt, "fd.types[3]"), "(bpf)");
	ASSERT_EQ(get_field_as_string(evt, "fd.types"), "(bpf,file)");
}
