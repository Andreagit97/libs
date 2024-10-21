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

#include <helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, EVT_FILTER_is_open_create) {
	add_default_init_thread();

	open_inspector();

	uint32_t flags = PPM_O_RDWR | PPM_O_CREAT | PPM_O_F_CREATED;
	auto evt = generate_open_event(sinsp_test_input::open_params{.flags = flags});
	ASSERT_EQ(get_field_as_string(evt, "evt.is_open_create"), "true");
	ASSERT_TRUE(evt->get_fd_info());
	ASSERT_EQ(evt->get_fd_info()->m_openflags, flags);
}

TEST_F(sinsp_with_test_input, EVT_FILTER_rawarg_int) {
	add_default_init_thread();

	open_inspector();

	sinsp_evt* evt =
	        add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_SETUID_E, 1, (uint32_t)1000);
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.uid"), "1000");
}

TEST_F(sinsp_with_test_input, EVT_FILTER_rawarg_str) {
	add_default_init_thread();

	open_inspector();

	auto evt = generate_open_event();
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.name"),
	          sinsp_test_input::open_params::default_path);
}

TEST_F(sinsp_with_test_input, EVT_FILTER_cmd_str) {
	add_default_init_thread();

	open_inspector();

	uint64_t fd = 1;

	sinsp_evt* evt = add_event_advance_ts(increasing_ts(),
	                                      1,
	                                      PPME_SYSCALL_BPF_2_X,
	                                      2,
	                                      fd,
	                                      PPM_BPF_PROG_LOAD);

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.cmd"), "BPF_PROG_LOAD");
}
TEST_F(sinsp_with_test_input, EVT_FILTER_check_evt_arg_uid) {
	add_default_init_thread();
	open_inspector();

	uint32_t user_id = 5;
	std::string container_id = "";
	auto evt = add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_SETUID_E, 1, user_id);
	ASSERT_EQ(get_field_as_string(evt, "evt.type"), "setuid");

	// The rawarg provides the field directly from the table.
	ASSERT_EQ(get_field_as_string(evt, "evt.rawarg.uid"), std::to_string(user_id));

	// The `evt.arg.uid` tries to find a user in the user table, in this
	// case the user table is empty.
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.uid"), "<NA>");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), "<NA>");
	ASSERT_EQ(get_field_as_string(evt, "evt.args"), "uid=5(<NA>)");

	// we are adding a user on the host so the `pid` parameter is not considered
	ASSERT_TRUE(m_inspector.m_usergroup_manager
	                    .add_user(container_id, 0, user_id, 6, "test", "/test", "/bin/test"));

	// Now we should have the necessary info
	ASSERT_EQ(get_field_as_string(evt, "evt.arg.uid"), "test");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), "test");
	ASSERT_EQ(get_field_as_string(evt, "evt.args"), "uid=5(test)");

	// We remove the user, and the fields should be empty again
	m_inspector.m_usergroup_manager.rm_user(container_id, user_id);
	ASSERT_FALSE(m_inspector.m_usergroup_manager.get_user(container_id, user_id));

	ASSERT_EQ(get_field_as_string(evt, "evt.arg.uid"), "<NA>");
	ASSERT_EQ(get_field_as_string(evt, "evt.arg[0]"), "<NA>");
	ASSERT_EQ(get_field_as_string(evt, "evt.args"), "uid=5(<NA>)");
}
