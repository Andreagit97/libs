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

TEST_F(sinsp_with_test_input, parse_open_success) {
	add_default_init_thread();
	open_inspector();

	int32_t fd = 5;
	uint32_t flags = PPM_O_APPEND | PPM_O_CREAT | PPM_O_RDWR;
	uint32_t mode = PPM_S_IRUSR | PPM_S_IWUSR | PPM_S_IRGRP | PPM_S_IROTH;
	uint32_t dev = 324;
	uint64_t ino = 534;

	// Assert file descriptor presence
	sinsp_threadinfo* init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(init_tinfo);

	// The default one
	ASSERT_EQ(init_tinfo->get_fd_opencount(), 1);

	auto evt = generate_open_event(
	        sinsp_test_input::open_params{.fd = fd,
	                                      .path = sinsp_test_input::open_params::default_path,
	                                      .flags = flags,
	                                      .mode = mode,
	                                      .dev = dev,
	                                      .ino = ino});

	// The default one + the one just opened
	ASSERT_EQ(init_tinfo->get_fd_opencount(), 2);

	assert_fd_fields(evt,
	                 sinsp_test_input::fd_info_fields{
	                         .fd_num = fd,
	                         .fd_name = sinsp_test_input::open_params::default_path,
	                         .fd_name_raw = sinsp_test_input::open_params::default_path,
	                         .fd_directory = sinsp_test_input::open_params::default_directory,
	                         .fd_filename = sinsp_test_input::open_params::default_filename});

	assert_return_value(evt, fd);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), sinsp_test_input::open_params::default_path);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.name"),
	          sinsp_test_input::open_params::default_path);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[2]"), "O_APPEND|O_CREAT|O_RDWR");
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.flags"), "F");

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[3]"),
	          "0644");  // octal notation of 420 formatted as string.
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.mode"), "644");

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[4]"), "144");  // hexadecimal notation
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.dev"), "144");

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[5]"), std::to_string(ino));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.ino"), std::to_string(ino));
}

TEST_F(sinsp_with_test_input, parse_open_failure) {
	add_default_init_thread();
	open_inspector();

	int32_t fd = -3;

	// Assert file descriptor presence
	sinsp_threadinfo* init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(init_tinfo);

	// At the beginning we have only the default file descriptor opened.
	ASSERT_EQ(init_tinfo->get_fd_opencount(), 1);

	auto evt = generate_open_event(sinsp_test_input::open_params{.fd = fd});

	// We should have only the default file descriptor opened, the event failed so no new file
	// descriptor should be created
	ASSERT_EQ(init_tinfo->get_fd_opencount(), 1);

	assert_fd_fields(
	        evt,
	        sinsp_test_input::fd_info_fields{
	                // we expect `-1` because m_lastevent_fd is set to -1 when the syscall fails.
	                .fd_num = -1,
	                .fd_name = sinsp_test_input::open_params::default_path,
	                .fd_name_raw = sinsp_test_input::open_params::default_path,
	                .fd_directory = sinsp_test_input::open_params::default_directory,
	                // We don't recover the filename
	        });

	assert_return_value(evt, fd);
}

TEST_F(sinsp_with_test_input, parse_open_path_too_long) {
	add_default_init_thread();

	open_inspector();

	std::stringstream long_path_ss;
	long_path_ss << "/";
	long_path_ss << std::string(1000, 'A');

	long_path_ss << "/";
	long_path_ss << std::string(1000, 'B');

	long_path_ss << "/";
	long_path_ss << std::string(1000, 'C');

	std::string long_path = long_path_ss.str();

	auto evt = generate_open_event(sinsp_test_input::open_params{.path = long_path.c_str()});

	assert_fd_fields(evt,
	                 sinsp_test_input::fd_info_fields{
	                         .fd_num = sinsp_test_input::open_params::default_fd,
	                         .fd_name = "/PATH_TOO_LONG",
	                         .fd_name_raw = long_path,
	                         // todo!: not ideal we probably want to fix this
	                         .fd_directory = "/",
	                         .fd_filename = "PATH_TOO_LONG",
	                 });
}
