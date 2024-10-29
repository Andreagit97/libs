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

TEST_F(sinsp_with_test_input, parse_read) {
	add_default_init_thread();
	open_inspector();

	auto evt = generate_open_event();

	std::string data = "hello";
	uint32_t size = data.size();
	evt = add_event_advance_ts(increasing_ts(),
	                           INIT_TID,
	                           PPME_SYSCALL_READ,
	                           4,
	                           (int32_t)size,
	                           scap_const_sized_buffer{data.c_str(), size},
	                           sinsp_test_input::open_params::default_fd,
	                           size);

	auto fdinfo = evt->get_fd_info();
	ASSERT_TRUE(fdinfo);
	ASSERT_EQ(fdinfo->m_fd, sinsp_test_input::open_params::default_fd);
	ASSERT_EQ(fdinfo->m_name, sinsp_test_input::open_params::default_path);

	EXPECT_EQ(get_field_as_string(evt, "fd.num"),
	          std::to_string(sinsp_test_input::open_params::default_fd));

	// Filter checks on the parameters
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), std::to_string(size));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.res32_rename"), std::to_string(size));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[1]"), data);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.data"), data);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[2]"),
	          std::string("<f>") + sinsp_test_input::open_params::default_path);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.fd32_rename"),
	          std::to_string(sinsp_test_input::open_params::default_fd));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg[3]"), std::to_string(size));
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.size"), std::to_string(size));
}
