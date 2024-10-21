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

#include <test/helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, open_success) {
	add_default_init_thread();
	open_inspector();

	sinsp_evt* evt = generate_open_event();
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN);

	// Assert file descriptor presence
	sinsp_threadinfo* init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(init_tinfo);

	sinsp_fdinfo* fdinfo = init_tinfo->get_fd(sinsp_test_input::open_params::default_fd);
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_name, sinsp_test_input::open_params::default_path);

	// Assert some filterchecks
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), sinsp_test_input::open_params::default_path);
	ASSERT_EQ(get_field_as_string(evt, "fd.directory"),
	          sinsp_test_input::open_params::default_directory);
	ASSERT_EQ(get_field_as_string(evt, "fd.filename"),
	          sinsp_test_input::open_params::default_filename);
}

TEST_F(sinsp_with_test_input, open_failure) {
	add_default_init_thread();
	open_inspector();

	sinsp_evt* evt = generate_open_event(sinsp_test_input::open_params{.fd = -1});
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN);

	// Assert file descriptor presence
	sinsp_threadinfo* init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(init_tinfo);

	sinsp_fdinfo* fdinfo = init_tinfo->get_fd(sinsp_test_input::open_params::default_fd);
	ASSERT_FALSE(fdinfo);

	// Assert some filterchecks
	ASSERT_FALSE(field_has_value(evt, "fd.name"));
	ASSERT_FALSE(field_has_value(evt, "fd.directory"));
	ASSERT_FALSE(field_has_value(evt, "fd.filename"));
}

TEST_F(sinsp_with_test_input, open_path_too_long) {
	add_default_init_thread();

	open_inspector();
	sinsp_evt* evt = NULL;

	std::stringstream long_path_ss;
	long_path_ss << "/";
	long_path_ss << std::string(1000, 'A');

	long_path_ss << "/";
	long_path_ss << std::string(1000, 'B');

	long_path_ss << "/";
	long_path_ss << std::string(1000, 'C');

	std::string long_path = long_path_ss.str();

	evt = generate_open_event(sinsp_test_input::open_params{.fd = 3, .path = long_path.c_str()});
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/PATH_TOO_LONG");

	int64_t fd = 4, mountfd = 5;
	add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
	evt = add_event_advance_ts(increasing_ts(),
	                           1,
	                           PPME_SYSCALL_OPEN_BY_HANDLE_AT_X,
	                           4,
	                           fd,
	                           mountfd,
	                           PPM_O_RDWR,
	                           long_path.c_str());

	ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/PATH_TOO_LONG");
	ASSERT_EQ(get_field_as_string(evt, "evt.abspath"), "/PATH_TOO_LONG");
}
