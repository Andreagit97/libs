#include <gtest/gtest.h>
#include <sinsp.h>

/* Check the `info` API works correctly */
TEST(events, check_event_info)
{
	{
		auto event_info_pointer = libsinsp::events::info(ppm_event_code::PPME_GENERIC_E);
		ASSERT_STREQ(event_info_pointer->name, "syscall");
		ASSERT_EQ(event_info_pointer->category, ppm_event_category(EC_OTHER | EC_SYSCALL));
		ASSERT_EQ(event_info_pointer->flags, EF_NONE);
		ASSERT_EQ(event_info_pointer->nparams, 2);
		ASSERT_STREQ(event_info_pointer->params[0].name, "ID");
	}

	{
		auto event_info_pointer = libsinsp::events::info(ppm_event_code::PPME_SYSCALL_CLONE3_X);
		ASSERT_STREQ(event_info_pointer->name, "clone3");
		ASSERT_EQ(event_info_pointer->category, ppm_event_category(EC_PROCESS | EC_SYSCALL));
		ASSERT_EQ(event_info_pointer->flags, EF_MODIFIES_STATE);
		ASSERT_EQ(event_info_pointer->nparams, 21);
		ASSERT_STREQ(event_info_pointer->params[0].name, "res");
	}
}

/* Check the `is_generic` API works correctly */
TEST(events, check_generic_events)
{
	ASSERT_EQ(libsinsp::events::is_generic(ppm_event_code::PPME_GENERIC_E), true);
	ASSERT_EQ(libsinsp::events::is_generic(ppm_event_code::PPME_GENERIC_X), true);
	ASSERT_EQ(libsinsp::events::is_generic(ppm_event_code::PPME_SYSCALL_CLONE3_X), false);
	ASSERT_EQ(libsinsp::events::is_generic(ppm_event_code::PPME_PLUGINEVENT_E), false);
}

/* Check the `is_unused_event` API works correctly */
TEST(events, check_unused_events)
{
	/* `PPME_SYSCALL_EXECVE_8_E` has the `EF_OLD_VERSION` flag */
	ASSERT_EQ(libsinsp::events::is_unused_event(PPME_SYSCALL_EXECVE_8_E), false);

	/* `PPME_SCHEDSWITCH_6_X` has the `EF_UNUSED` flag */
	ASSERT_EQ(libsinsp::events::is_unused_event(PPME_SCHEDSWITCH_6_X), true);

	/* `PPME_SYSCALL_QUOTACTL_E` has no flags in this set */
	ASSERT_EQ(libsinsp::events::is_unused_event(PPME_SYSCALL_QUOTACTL_E), false);
}

/* Check the `is_skip_parse_reset_event` API works correctly */
TEST(events, check_skip_parse_reset_events)
{
	ASSERT_EQ(libsinsp::events::is_skip_parse_reset_event(ppm_event_code::PPME_PROCINFO_E), true);
	ASSERT_EQ(libsinsp::events::is_skip_parse_reset_event(ppm_event_code::PPME_SYSCALL_GETDENTS_E), false);
	ASSERT_EQ(libsinsp::events::is_skip_parse_reset_event(ppm_event_code::PPME_PLUGINEVENT_E), false);
}

/* Check the `is_old_version_event` API works correctly */
TEST(events, check_old_version_events)
{
	/* `PPME_SYSCALL_EXECVE_8_E` has only the `EF_OLD_VERSION` flag */
	ASSERT_EQ(libsinsp::events::is_old_version_event(PPME_SYSCALL_EXECVE_14_E), true);

	/* `PPME_SCHEDSWITCH_6_X` has no the `EF_OLD_VERSION` flag */
	ASSERT_EQ(libsinsp::events::is_old_version_event(PPME_SCHEDSWITCH_6_X), false);
}

/* Check if the events category is correct */
TEST(events, check_events_category)
{
	/* Assert that the API works good */
	ASSERT_EQ(libsinsp::events::is_syscall_event(PPME_SYSCALL_EXECVE_8_E), true);
	ASSERT_EQ(libsinsp::events::is_syscall_event(PPME_SCHEDSWITCH_6_X), false);

	ASSERT_EQ(libsinsp::events::is_tracepoint_event(PPME_SCHEDSWITCH_6_E), true);
	ASSERT_EQ(libsinsp::events::is_tracepoint_event(PPME_SYSCALL_CLONE_20_E), false);

	ASSERT_EQ(libsinsp::events::is_metaevent(PPME_DROP_E), true);
	ASSERT_EQ(libsinsp::events::is_metaevent(PPME_SYSCALL_CLONE_20_X), false);

	ASSERT_EQ(libsinsp::events::is_unknown_event(PPME_SCHEDSWITCH_1_X), true);
	ASSERT_EQ(libsinsp::events::is_unknown_event(PPME_SYSCALL_CLONE_20_E), false);

	ASSERT_EQ(libsinsp::events::is_plugin_event(PPME_PLUGINEVENT_E), true);
	ASSERT_EQ(libsinsp::events::is_plugin_event(PPME_SYSCALL_CLONE_20_E), false);
}

TEST(events, event_set_to_names)
{
	/* These 2 sets should be equal */
	const auto generic_e_event_names = libsinsp::events::event_set_to_names({ppm_event_code::PPME_GENERIC_X});
	const auto generic_x_event_names = libsinsp::events::event_set_to_names({ppm_event_code::PPME_GENERIC_X});
	ASSERT_EQ(generic_e_event_names, generic_x_event_names);
	ASSERT_TRUE(generic_x_event_names.find("io_submit") != generic_x_event_names.end());

	/* Coming back to generic events */
	const auto generic_e_set = libsinsp::events::names_to_event_set(generic_e_event_names);
	const auto generic_x_set = libsinsp::events::names_to_event_set(generic_x_event_names);
	libsinsp::events::set<ppm_event_code> generic_set = {PPME_GENERIC_E, PPME_GENERIC_X};
	ASSERT_EQ(generic_e_set, generic_set);
	ASSERT_EQ(generic_e_set, generic_x_set);
}
