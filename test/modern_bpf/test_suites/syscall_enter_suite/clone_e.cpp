#include "../../event_class/event_class.h"

#ifdef __NR_clone
TEST(SyscallEnter, cloneE)
{
	auto evt_test = new event_test(__NR_clone, ENTER_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL  ===========================*/

	/* flags are invalid so the syscall will fail. */
	unsigned long clone_flags = (unsigned long)-1;
	unsigned long newsp = 0;
	int parent_tid = -1;
	int child_tid = -1;
	unsigned long tls = 0;
	assert_syscall_state(SYSCALL_FAILURE, "clone", syscall(__NR_clone, clone_flags, newsp, &parent_tid, &child_tid, tls));

	/*=============================== TRIGGER SYSCALL  ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	// Here we have no parameters to assert.

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(0);
}
#endif
