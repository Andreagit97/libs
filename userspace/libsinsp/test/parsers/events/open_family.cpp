#include <test/helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, open_simple) {
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = generate_open_event();
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_OPEN);
	ASSERT_EQ(get_field_as_string(evt, "fd.name"), sinsp_test_input::open_params::default_path);
	ASSERT_EQ(get_field_as_string(evt, "fd.directory"),
	          sinsp_test_input::open_params::default_directory);
	ASSERT_EQ(get_field_as_string(evt, "fd.filename"),
	          sinsp_test_input::open_params::default_filename);
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
